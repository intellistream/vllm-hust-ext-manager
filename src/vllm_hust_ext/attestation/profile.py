"""RFC 8785 JCS + detached compact JWS + Ed25519 candidate profile."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .model import PROFILE, SCHEMA, AttestationStatement

TYPE = "application/ecpa-attestation+jws"
ALGORITHM = "EdDSA"
KNOWN_CRITICAL_HEADERS = frozenset({"ecpa_profile"})
KNOWN_CRITICAL_CLAIMS = frozenset()
MAX_SAFE_INTEGER = 2**53 - 1


class AttestationErrorCode(str, Enum):
    MALFORMED_JSON = "ATTESTATION_MALFORMED_JSON"
    DUPLICATE_KEY = "ATTESTATION_DUPLICATE_KEY"
    UNSUPPORTED_VALUE = "ATTESTATION_UNSUPPORTED_VALUE"
    NONCANONICAL_PAYLOAD = "ATTESTATION_NONCANONICAL_PAYLOAD"
    MALFORMED_JWS = "ATTESTATION_MALFORMED_JWS"
    WRONG_ALGORITHM = "ATTESTATION_WRONG_ALGORITHM"
    WRONG_TYPE = "ATTESTATION_WRONG_TYPE"
    WRONG_PROFILE = "ATTESTATION_WRONG_PROFILE"
    UNKNOWN_CRITICAL_HEADER = "ATTESTATION_UNKNOWN_CRITICAL_HEADER"
    UNKNOWN_CRITICAL_CLAIM = "ATTESTATION_UNKNOWN_CRITICAL_CLAIM"
    UNKNOWN_KEY = "ATTESTATION_UNKNOWN_KEY"
    KEY_MISMATCH = "ATTESTATION_KEY_MISMATCH"
    INVALID_SIGNATURE = "ATTESTATION_INVALID_SIGNATURE"
    NOT_YET_VALID = "ATTESTATION_NOT_YET_VALID"
    EXPIRED = "ATTESTATION_EXPIRED"
    BINDING_MISMATCH = "ATTESTATION_BINDING_MISMATCH"


class AttestationError(ValueError):
    def __init__(self, code: AttestationErrorCode, detail: str):
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise AttestationError(
            AttestationErrorCode.MALFORMED_JWS, "invalid base64url"
        ) from exc


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError(AttestationErrorCode.DUPLICATE_KEY, key)
        result[key] = value
    return result


def parse_strict(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                AttestationError(AttestationErrorCode.UNSUPPORTED_VALUE, value)
            ),
        )
    except AttestationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationError(AttestationErrorCode.MALFORMED_JSON, str(exc)) from exc
    if not isinstance(value, dict):
        raise AttestationError(
            AttestationErrorCode.MALFORMED_JSON, "top level must be object"
        )
    return value


def _validate_values(value: Any) -> None:
    if isinstance(value, float):
        raise AttestationError(
            AttestationErrorCode.UNSUPPORTED_VALUE,
            "profile 0.1 forbids floating-point claims",
        )
    if isinstance(value, int) and (
        value < -MAX_SAFE_INTEGER or value > MAX_SAFE_INTEGER
    ):
        raise AttestationError(
            AttestationErrorCode.UNSUPPORTED_VALUE, "integer exceeds I-JSON safe range"
        )
    if isinstance(value, dict):
        for item in value.values():
            _validate_values(item)
    elif isinstance(value, list):
        for item in value:
            _validate_values(item)


def canonicalize(value: dict[str, Any]) -> bytes:
    _validate_values(value)
    try:
        return bytes(jcs.canonicalize(value))
    except Exception as exc:
        raise AttestationError(
            AttestationErrorCode.UNSUPPORTED_VALUE, str(exc)
        ) from exc


@dataclass(frozen=True)
class SignedEnvelope:
    payload: bytes
    detached_jws: str


class TrustStore:
    def __init__(self, keys: dict[str, Ed25519PublicKey]):
        self._keys = dict(keys)

    def lookup(self, kid: str) -> Ed25519PublicKey:
        try:
            return self._keys[kid]
        except KeyError as exc:
            raise AttestationError(AttestationErrorCode.UNKNOWN_KEY, kid) from exc


def _protected(kid: str) -> dict[str, Any]:
    return {
        "alg": ALGORITHM,
        "crit": ["ecpa_profile"],
        "ecpa_profile": PROFILE,
        "kid": kid,
        "typ": TYPE,
    }


def sign(statement: AttestationStatement, key: Ed25519PrivateKey) -> SignedEnvelope:
    if statement.schema != SCHEMA or statement.profile != PROFILE:
        raise AttestationError(AttestationErrorCode.WRONG_PROFILE, statement.profile)
    payload = canonicalize(statement.to_dict())
    protected = canonicalize(_protected(statement.kid))
    encoded_header = _b64url(protected)
    signing_input = f"{encoded_header}.{_b64url(payload)}".encode("ascii")
    signature = _b64url(key.sign(signing_input))
    return SignedEnvelope(payload, f"{encoded_header}..{signature}")


def verify(
    envelope: SignedEnvelope,
    trust_store: TrustStore,
    now: int,
    clock_skew: int = 0,
) -> AttestationStatement:
    parts = envelope.detached_jws.split(".")
    if len(parts) != 3 or parts[1] != "":
        raise AttestationError(
            AttestationErrorCode.MALFORMED_JWS, "expected detached compact JWS"
        )
    header_raw = _b64url_decode(parts[0])
    header = parse_strict(header_raw)
    if header_raw != canonicalize(header):
        raise AttestationError(
            AttestationErrorCode.MALFORMED_JWS, "protected header is not canonical"
        )
    if header.get("alg") != ALGORITHM:
        raise AttestationError(
            AttestationErrorCode.WRONG_ALGORITHM, str(header.get("alg"))
        )
    if header.get("typ") != TYPE:
        raise AttestationError(AttestationErrorCode.WRONG_TYPE, str(header.get("typ")))
    if header.get("ecpa_profile") != PROFILE:
        raise AttestationError(
            AttestationErrorCode.WRONG_PROFILE, str(header.get("ecpa_profile"))
        )
    critical = header.get("crit")
    if not isinstance(critical, list) or any(
        item not in KNOWN_CRITICAL_HEADERS for item in critical
    ):
        raise AttestationError(
            AttestationErrorCode.UNKNOWN_CRITICAL_HEADER, str(critical)
        )
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise AttestationError(AttestationErrorCode.UNKNOWN_KEY, str(kid))
    payload_value = parse_strict(envelope.payload)
    if envelope.payload != canonicalize(payload_value):
        raise AttestationError(
            AttestationErrorCode.NONCANONICAL_PAYLOAD, "payload must be JCS bytes"
        )
    try:
        statement = AttestationStatement.from_dict(payload_value)
    except (TypeError, ValueError) as exc:
        raise AttestationError(AttestationErrorCode.MALFORMED_JSON, str(exc)) from exc
    if statement.schema != SCHEMA or statement.profile != PROFILE:
        raise AttestationError(AttestationErrorCode.WRONG_PROFILE, statement.profile)
    if statement.kid != kid:
        raise AttestationError(AttestationErrorCode.KEY_MISMATCH, statement.kid)
    unknown_claims = set(statement.critical_claims) - KNOWN_CRITICAL_CLAIMS
    if unknown_claims:
        raise AttestationError(
            AttestationErrorCode.UNKNOWN_CRITICAL_CLAIM,
            ",".join(sorted(unknown_claims)),
        )
    signing_input = f"{parts[0]}.{_b64url(envelope.payload)}".encode("ascii")
    try:
        trust_store.lookup(kid).verify(_b64url_decode(parts[2]), signing_input)
    except InvalidSignature as exc:
        raise AttestationError(AttestationErrorCode.INVALID_SIGNATURE, kid) from exc
    if (
        statement.issued_at > now + clock_skew
        or statement.observed_at > now + clock_skew
    ):
        raise AttestationError(AttestationErrorCode.NOT_YET_VALID, statement.kid)
    if statement.expires_at < now - clock_skew:
        raise AttestationError(AttestationErrorCode.EXPIRED, statement.kid)
    return statement


class SignedAttestationVerifier:
    """Adapter for coordinator verification; coordinator retains policy authority."""

    def __init__(
        self,
        envelopes: dict[str, SignedEnvelope],
        trust_store: TrustStore,
        artifact_digests: dict[str, str],
        clock_skew: int = 0,
    ):
        self.envelopes = envelopes
        self.trust_store = trust_store
        self.artifact_digests = artifact_digests
        self.clock_skew = clock_skew

    def verify(self, attestation: Any, now: int) -> None:
        try:
            envelope = self.envelopes[attestation.nonce]
        except KeyError as exc:
            raise AttestationError(
                AttestationErrorCode.BINDING_MISMATCH, "missing signed envelope"
            ) from exc
        statement = verify(envelope, self.trust_store, now, self.clock_skew)
        expected_digest = self.artifact_digests.get(attestation.artifact_id)
        if expected_digest is None or statement.artifact_digest != expected_digest:
            raise AttestationError(
                AttestationErrorCode.BINDING_MISMATCH,
                "statement does not bind the expected artifact digest",
            )
        expected = {
            "subject": attestation.authority,
            "plan_id": attestation.plan_id,
            "launch_id": attestation.launch_id,
            "plugin_id": attestation.artifact_id,
            "host": attestation.process.host,
            "role": attestation.process.role,
            "ordinal": attestation.process.ordinal,
            "start_identity": attestation.process.start_id,
            "epoch": attestation.process.epoch,
            "obligation": attestation.obligation_id,
            "event": attestation.event,
            "issued_at": attestation.issued_at,
            "expires_at": attestation.expires_at,
            "challenge_nonce": attestation.nonce,
        }
        actual = {
            "subject": statement.subject,
            "plan_id": statement.plan_id,
            "launch_id": statement.launch_id,
            "plugin_id": statement.plugin_id,
            "host": statement.process.host,
            "role": statement.process.role,
            "ordinal": statement.process.ordinal,
            "start_identity": statement.process.start_identity,
            "epoch": statement.process.epoch,
            "obligation": statement.obligation,
            "event": statement.event,
            "issued_at": statement.issued_at,
            "expires_at": statement.expires_at,
            "challenge_nonce": statement.challenge_nonce,
        }
        if actual != expected:
            raise AttestationError(
                AttestationErrorCode.BINDING_MISMATCH, "statement does not bind receipt"
            )
