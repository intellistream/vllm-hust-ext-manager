# ECPA Attestation Profile 0.1 (candidate)

Status: candidate profile for ECPA 0.1. It is not an
industry standard and does not require TPM, TEE, or hardware-backed keys.

## Three boundaries

1. **Standard statement semantics** bind issuer/key, subject authority, plan,
   launch, plugin/artifact, host process identity and epoch, obligation/event,
   observation/issuance/expiry times, challenge nonce, and evidence digest.
   These meanings are encoding-independent.
2. **Profile encoding** uses RFC 8785 JSON Canonicalization Scheme (JCS), a
   detached compact JWS signing input
   `BASE64URL(protected) || "." || BASE64URL(JCS(statement))`, and Ed25519 with
   JWS `alg=EdDSA`. The protected header fixes `typ`, `kid`, `ecpa_profile`, and
   marks `ecpa_profile` critical.
3. **Deployment trust policy** decides which issuer/key IDs and authorities are
   trusted, distributes/revokes keys, chooses clock skew, and maps a valid
   statement into a deployment's evidence policy. Signature validity alone
   never implies ECPA `Effective`.

Python uses the maintained `jcs==0.2.1` package for RFC 8785 canonicalization
and `cryptography` Ed25519. A separate Go implementation passing the shared
corpus uses
`github.com/cyberphone/json-canonicalization` and Go's standard Ed25519/JSON
libraries. Profile 0.1 forbids floating-point claims and integers outside the
I-JSON safe range. Duplicate keys, NaN/Infinity, malformed UTF-8, unknown
critical fields, and noncanonical signed payload bytes fail closed. Unicode is
preserved exactly; no normalization is silently applied.

## Key rotation and revocation

The conformance trust store contains two `kid` values and TEST ONLY deterministic
seeds. They are public test material and must never be used in production.
Multiple key IDs demonstrate overlap during rotation. Revocation distribution,
issuer enrollment, secure private-key custody, and production trust roots are
deployment-policy work outside this milestone.
Revocation policy epochs and distribution remain explicitly deferred; an
enabled flag and validity interval are boundaries, not a production revocation
mechanism.

Each trust-store entry binds `(issuer, kid)` to allowed subjects/authorities,
an enabled state, and a validity interval. The verifier also enforces
`observed_at <= issued_at <= expires_at`, a maximum TTL, and a maximum
observation age before ingestion.

`evidence_digest` is a persistent audit binding: the issuer computes SHA-256
over the exact raw host-evidence bytes it observed and records
`sha256:<lowercase hex>`. This milestone validates the format, signature, and
receipt binding and persists the digest. It does not receive those raw bytes,
so it does not claim to have recomputed or content-verified the digest.

## Coordinator authority

`SignedAttestationVerifier` verifies the envelope and binds every coordinator
receipt field to the signed statement before ingestion. The durable SQLite
store remains the nonce uniqueness/replay fence. Inventory epoch, required
process coverage, obligation satisfaction, generation CAS, and ExposureGate
commit remain coordinator decisions.

Existing databases are migrated additively for issuer, kid, observed time,
evidence digest, and artifact digest. Legacy rows receive empty/zero defaults
and are not retroactively treated as signed evidence.

## Conformance

Generate vectors:

```console
PYTHONPATH=src python3 scripts/generate_attestation_vectors.py
```

Verify Python and Go:

```console
PYTHONPATH=src python3 scripts/check_attestation_vectors.py
cd tools/attestation-go && go test ./... && go run . ../../spec/0.1/attestation-vectors.json
```

The checked-in vectors contain expected verdicts/error codes. Missing
measurements remain `null`, never zero.
