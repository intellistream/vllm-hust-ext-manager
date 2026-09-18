// Independent ECPA Attestation Profile 0.1 vector verifier.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	jcs "github.com/intellistream/ecpa-attestation-cleanroom/internal/jcs"
)

const profile = "ecpa-jcs-jws-eddsa/0.1"
const mediaType = "application/ecpa-attestation+jws"
const maxSafeInteger = int64(9007199254740991)

type vectorFile struct {
	Keys  []keyVector  `json:"keys"`
	Cases []caseVector `json:"cases"`
}
type keyVector struct {
	Issuer       string   `json:"issuer"`
	Kid          string   `json:"kid"`
	PublicKeyB64 string   `json:"public_key_b64"`
	Subjects     []string `json:"subjects"`
	Enabled      bool     `json:"enabled"`
	NotBefore    int64    `json:"not_before"`
	NotAfter     int64    `json:"not_after"`
}
type binding struct {
	PlanID         string `json:"plan_id"`
	LaunchID       string `json:"launch_id"`
	PluginID       string `json:"plugin_id"`
	ArtifactDigest string `json:"artifact_digest"`
	ChallengeNonce string `json:"challenge_nonce"`
	ProcessEpoch   int64  `json:"process_epoch"`
}
type caseVector struct {
	ID          string   `json:"id"`
	PayloadB64  string   `json:"payload_b64"`
	DetachedJWS string   `json:"detached_jws"`
	Expected    string   `json:"expected"`
	Now         int64    `json:"now"`
	Binding     *binding `json:"binding"`
}
type statement struct {
	Schema         string `json:"schema"`
	Profile        string `json:"profile"`
	Issuer         string `json:"issuer"`
	Kid            string `json:"kid"`
	Subject        string `json:"subject"`
	PlanID         string `json:"plan_id"`
	LaunchID       string `json:"launch_id"`
	PluginID       string `json:"plugin_id"`
	ArtifactDigest string `json:"artifact_digest"`
	Process        struct {
		Host          string `json:"host"`
		Role          string `json:"role"`
		StartIdentity string `json:"start_identity"`
		Ordinal       int64  `json:"ordinal"`
		Epoch         int64  `json:"epoch"`
	} `json:"process"`
	Obligation     string   `json:"obligation"`
	Event          string   `json:"event"`
	ObservedAt     int64    `json:"observed_at"`
	IssuedAt       int64    `json:"issued_at"`
	ExpiresAt      int64    `json:"expires_at"`
	ChallengeNonce string   `json:"challenge_nonce"`
	EvidenceDigest string   `json:"evidence_digest"`
	CriticalClaims []string `json:"critical_claims"`
}
type header struct {
	Alg         string   `json:"alg"`
	Kid         string   `json:"kid"`
	Typ         string   `json:"typ"`
	ECPAProfile string   `json:"ecpa_profile"`
	Crit        []string `json:"crit"`
}
type codedError string

func (e codedError) Error() string { return string(e) }

var b64 = base64.RawURLEncoding

func decodeB64(value string) ([]byte, error) {
	if strings.Contains(value, "=") || len(value)%4 == 1 {
		return nil, codedError("ATTESTATION_MALFORMED_JWS")
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return nil, codedError("ATTESTATION_MALFORMED_JWS")
		}
	}
	raw, err := b64.DecodeString(value)
	if err != nil || b64.EncodeToString(raw) != value {
		return nil, codedError("ATTESTATION_MALFORMED_JWS")
	}
	return raw, nil
}

func containsNonFiniteToken(raw []byte) bool {
	inString, escaped := false, false
	var outside strings.Builder
	for _, c := range string(raw) {
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		outside.WriteRune(c)
	}
	text := outside.String()
	return strings.Contains(text, "NaN") || strings.Contains(text, "Infinity")
}

func parseStrict(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, codedError("ATTESTATION_MALFORMED_JSON")
	}
	if containsNonFiniteToken(raw) {
		return nil, codedError("ATTESTATION_UNSUPPORTED_VALUE")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, codedError("ATTESTATION_MALFORMED_JSON")
	}
	if token, err := dec.Token(); err == nil || token != nil {
		return nil, codedError("ATTESTATION_MALFORMED_JSON")
	}
	return value, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, codedError("ATTESTATION_MALFORMED_JSON")
	}
	switch value := token.(type) {
	case json.Delim:
		if value == '{' {
			obj := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, codedError("ATTESTATION_MALFORMED_JSON")
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, codedError("ATTESTATION_MALFORMED_JSON")
				}
				if _, exists := obj[key]; exists {
					return nil, codedError("ATTESTATION_DUPLICATE_KEY")
				}
				item, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = item
			}
			if _, err := dec.Token(); err != nil {
				return nil, codedError("ATTESTATION_MALFORMED_JSON")
			}
			return obj, nil
		}
		if value == '[' {
			items := []any{}
			for dec.More() {
				item, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				items = append(items, item)
			}
			if _, err := dec.Token(); err != nil {
				return nil, codedError("ATTESTATION_MALFORMED_JSON")
			}
			return items, nil
		}
	case json.Number:
		s := value.String()
		if strings.ContainsAny(s, ".eE") {
			return nil, codedError("ATTESTATION_UNSUPPORTED_VALUE")
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil || i > maxSafeInteger || i < -maxSafeInteger {
			return nil, codedError("ATTESTATION_UNSUPPORTED_VALUE")
		}
		return i, nil
	}
	return token, nil
}

func code(err error) string {
	var coded codedError
	if errors.As(err, &coded) {
		return string(coded)
	}
	return "ATTESTATION_MALFORMED_JSON"
}

func exactKeys(value map[string]any, names ...string) bool {
	if len(value) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := value[name]; !ok {
			return false
		}
	}
	return true
}

func nonEmpty(value any) bool { text, ok := value.(string); return ok && text != "" }

func validateStatementMap(value map[string]any) string {
	if !exactKeys(value, "schema", "profile", "issuer", "kid", "subject", "plan_id", "launch_id", "plugin_id", "artifact_digest", "process", "obligation", "event", "observed_at", "issued_at", "expires_at", "challenge_nonce", "evidence_digest", "critical_claims") {
		return "ATTESTATION_INVALID_STATEMENT"
	}
	for _, name := range []string{"schema", "profile", "issuer", "kid", "subject", "plan_id", "launch_id", "plugin_id", "artifact_digest", "obligation", "event", "challenge_nonce", "evidence_digest"} {
		if !nonEmpty(value[name]) {
			return "ATTESTATION_INVALID_STATEMENT"
		}
	}
	process, ok := value["process"].(map[string]any)
	if !ok || !exactKeys(process, "host", "role", "ordinal", "start_identity", "epoch") {
		return "ATTESTATION_INVALID_STATEMENT"
	}
	for _, name := range []string{"host", "role", "start_identity"} {
		if !nonEmpty(process[name]) {
			return "ATTESTATION_INVALID_STATEMENT"
		}
	}
	for _, item := range []any{process["ordinal"], process["epoch"], value["observed_at"], value["issued_at"], value["expires_at"]} {
		number, ok := item.(int64)
		if !ok || number < 0 || number > maxSafeInteger {
			return "ATTESTATION_INVALID_STATEMENT"
		}
	}
	for _, name := range []string{"artifact_digest", "evidence_digest"} {
		text := value[name].(string)
		if len(text) != 71 || !strings.HasPrefix(text, "sha256:") {
			return "ATTESTATION_INVALID_STATEMENT"
		}
		for _, c := range text[7:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return "ATTESTATION_INVALID_STATEMENT"
			}
		}
	}
	claims, ok := value["critical_claims"].([]any)
	if !ok {
		return "ATTESTATION_INVALID_STATEMENT"
	}
	seen := map[string]bool{}
	for _, item := range claims {
		text, ok := item.(string)
		if !ok || seen[text] {
			return "ATTESTATION_INVALID_STATEMENT"
		}
		seen[text] = true
	}
	return ""
}

func verifyCase(c caseVector, keys map[string]keyVector, seen map[string]bool) string {
	payload, err := b64.DecodeString(c.PayloadB64)
	if err != nil {
		return "ATTESTATION_MALFORMED_JSON"
	}
	parts := strings.Split(c.DetachedJWS, ".")
	if len(parts) != 3 || parts[1] != "" {
		return "ATTESTATION_MALFORMED_JWS"
	}
	headerRaw, err := decodeB64(parts[0])
	if err != nil {
		return "ATTESTATION_MALFORMED_JWS"
	}
	headerValue, err := parseStrict(headerRaw)
	if err != nil {
		return code(err)
	}
	headerMap, ok := headerValue.(map[string]any)
	if !ok || !exactKeys(headerMap, "alg", "crit", "ecpa_profile", "kid", "typ") {
		return "ATTESTATION_UNKNOWN_CRITICAL_HEADER"
	}
	critValue, ok := headerMap["crit"].([]any)
	if !ok || len(critValue) != 1 {
		return "ATTESTATION_UNKNOWN_CRITICAL_HEADER"
	}
	critName, ok := critValue[0].(string)
	if !ok || critName != "ecpa_profile" {
		return "ATTESTATION_UNKNOWN_CRITICAL_HEADER"
	}
	canonHeader, err := jcs.Transform(headerRaw)
	if err != nil || !bytes.Equal(canonHeader, headerRaw) {
		return "ATTESTATION_MALFORMED_JWS"
	}
	var h header
	headerDecoder := json.NewDecoder(bytes.NewReader(headerRaw))
	headerDecoder.DisallowUnknownFields()
	if headerDecoder.Decode(&h) != nil {
		return "ATTESTATION_MALFORMED_JWS"
	}
	if h.Alg != "EdDSA" {
		return "ATTESTATION_WRONG_ALGORITHM"
	}
	if h.Typ != mediaType {
		return "ATTESTATION_WRONG_TYPE"
	}
	if len(h.Crit) != 1 || h.Crit[0] != "ecpa_profile" {
		return "ATTESTATION_UNKNOWN_CRITICAL_HEADER"
	}
	if h.ECPAProfile != profile {
		return "ATTESTATION_WRONG_PROFILE"
	}
	payloadValue, err := parseStrict(payload)
	if err != nil {
		return code(err)
	}
	payloadMap, ok := payloadValue.(map[string]any)
	if !ok {
		return "ATTESTATION_INVALID_STATEMENT"
	}
	canonical, err := jcs.Transform(payload)
	if err != nil {
		return "ATTESTATION_UNSUPPORTED_VALUE"
	}
	if !bytes.Equal(canonical, payload) {
		return "ATTESTATION_NONCANONICAL_PAYLOAD"
	}
	if outcome := validateStatementMap(payloadMap); outcome != "" {
		return outcome
	}
	var s statement
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s) != nil {
		return "ATTESTATION_INVALID_STATEMENT"
	}
	if s.Profile != profile || s.Schema != "ecpa-attestation-statement/0.1" {
		return "ATTESTATION_WRONG_PROFILE"
	}
	if s.Kid != h.Kid {
		return "ATTESTATION_KEY_MISMATCH"
	}
	if len(s.CriticalClaims) != 0 {
		return "ATTESTATION_UNKNOWN_CRITICAL_CLAIM"
	}
	key, ok := keys[s.Issuer+"\x00"+h.Kid]
	if !ok {
		return "ATTESTATION_UNKNOWN_KEY"
	}
	allowed := false
	for _, subject := range key.Subjects {
		if subject == s.Subject {
			allowed = true
		}
	}
	if !key.Enabled || !allowed || c.Now < key.NotBefore || c.Now > key.NotAfter {
		return "ATTESTATION_TRUST_POLICY"
	}
	sig, err := decodeB64(parts[2])
	if err != nil {
		return "ATTESTATION_MALFORMED_JWS"
	}
	input := []byte(parts[0] + "." + b64.EncodeToString(payload))
	public, err := b64.DecodeString(key.PublicKeyB64)
	if err != nil {
		return "ATTESTATION_UNKNOWN_KEY"
	}
	if !ed25519.Verify(ed25519.PublicKey(public), input, sig) {
		return "ATTESTATION_INVALID_SIGNATURE"
	}
	if s.IssuedAt > c.Now || s.ObservedAt > c.Now {
		return "ATTESTATION_NOT_YET_VALID"
	}
	if s.ExpiresAt < c.Now {
		return "ATTESTATION_EXPIRED"
	}
	if !(s.ObservedAt <= s.IssuedAt && s.IssuedAt <= s.ExpiresAt) || s.ExpiresAt-s.IssuedAt > 300 || c.Now-s.ObservedAt > 300 {
		return "ATTESTATION_INVALID_TIME"
	}
	if c.Binding != nil && (s.PlanID != c.Binding.PlanID || s.LaunchID != c.Binding.LaunchID || s.PluginID != c.Binding.PluginID || s.ArtifactDigest != c.Binding.ArtifactDigest || s.Process.Epoch != c.Binding.ProcessEpoch || s.ChallengeNonce != c.Binding.ChallengeNonce) {
		return "ATTESTATION_BINDING_MISMATCH"
	}
	if c.Binding != nil && seen[s.ChallengeNonce] {
		return "REPLAYED_NONCE"
	}
	if c.Binding != nil {
		seen[s.ChallengeNonce] = true
	}
	return "OK"
}

func run(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		return err
	}
	keys := map[string]keyVector{}
	for _, item := range vectors.Keys {
		raw, err := b64.DecodeString(item.PublicKeyB64)
		if err != nil {
			return err
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid public key")
		}
		keys[item.Issuer+"\x00"+item.Kid] = item
	}
	seen := map[string]bool{}
	failures := 0
	for _, item := range vectors.Cases {
		outcome := verifyCase(item, keys, seen)
		if outcome != item.Expected {
			fmt.Printf("%s expected=%s actual=%s\n", item.ID, item.Expected, outcome)
			failures++
		}
	}
	if failures != 0 {
		return fmt.Errorf("%d vector mismatches", failures)
	}
	fmt.Printf("Go attestation conformance: %d vectors passed\n", len(vectors.Cases))
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: attestation-go vectors.json")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
