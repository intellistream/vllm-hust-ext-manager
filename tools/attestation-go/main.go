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
	Kid          string `json:"kid"`
	PublicKeyB64 string `json:"public_key_b64"`
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

func parseStrict(raw []byte) (any, error) {
	if bytes.Contains(raw, []byte("NaN")) || bytes.Contains(raw, []byte("Infinity")) {
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

func verifyCase(c caseVector, keys map[string]ed25519.PublicKey, seen map[string]bool) string {
	payload, err := b64.DecodeString(c.PayloadB64)
	if err != nil {
		return "ATTESTATION_MALFORMED_JSON"
	}
	parts := strings.Split(c.DetachedJWS, ".")
	if len(parts) != 3 || parts[1] != "" {
		return "ATTESTATION_MALFORMED_JWS"
	}
	headerRaw, err := b64.DecodeString(parts[0])
	if err != nil {
		return "ATTESTATION_MALFORMED_JWS"
	}
	if _, err = parseStrict(headerRaw); err != nil {
		return code(err)
	}
	canonHeader, err := jcs.Transform(headerRaw)
	if err != nil || !bytes.Equal(canonHeader, headerRaw) {
		return "ATTESTATION_MALFORMED_JWS"
	}
	var h header
	if json.Unmarshal(headerRaw, &h) != nil {
		return "ATTESTATION_MALFORMED_JWS"
	}
	if h.Alg != "EdDSA" {
		return "ATTESTATION_WRONG_ALGORITHM"
	}
	if h.Typ != mediaType {
		return "ATTESTATION_WRONG_TYPE"
	}
	if h.ECPAProfile != profile {
		return "ATTESTATION_WRONG_PROFILE"
	}
	if len(h.Crit) != 1 || h.Crit[0] != "ecpa_profile" {
		return "ATTESTATION_UNKNOWN_CRITICAL_HEADER"
	}
	if _, err = parseStrict(payload); err != nil {
		return code(err)
	}
	canonical, err := jcs.Transform(payload)
	if err != nil {
		return "ATTESTATION_UNSUPPORTED_VALUE"
	}
	if !bytes.Equal(canonical, payload) {
		return "ATTESTATION_NONCANONICAL_PAYLOAD"
	}
	var s statement
	if json.Unmarshal(payload, &s) != nil {
		return "ATTESTATION_MALFORMED_JSON"
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
	key, ok := keys[h.Kid]
	if !ok {
		return "ATTESTATION_UNKNOWN_KEY"
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return "ATTESTATION_MALFORMED_JWS"
	}
	input := []byte(parts[0] + "." + b64.EncodeToString(payload))
	if !ed25519.Verify(key, input, sig) {
		return "ATTESTATION_INVALID_SIGNATURE"
	}
	if s.IssuedAt > c.Now || s.ObservedAt > c.Now {
		return "ATTESTATION_NOT_YET_VALID"
	}
	if s.ExpiresAt < c.Now {
		return "ATTESTATION_EXPIRED"
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
	keys := map[string]ed25519.PublicKey{}
	for _, item := range vectors.Keys {
		raw, err := b64.DecodeString(item.PublicKeyB64)
		if err != nil {
			return err
		}
		keys[item.Kid] = ed25519.PublicKey(raw)
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
