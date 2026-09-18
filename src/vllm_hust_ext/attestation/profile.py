"""RFC 8785 JCS + detached compact JWS + Ed25519 candidate profile."""

from __future__ import annotations

import base64
import json
import re
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
DEFAULT_MAX_TTL = 300
DEFAULT_MAX_OBSERVATION_AGE = 300
BASE64URL = re.compile(r"^[A-Za-z0-9_-]*$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


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
    INVALID_STATEMENT = "ATTESTATION_INVALID_STATEMENT"
    INVALID_TIME = "ATTESTATION_INVALID_TIME"
    TRUST_POLICY = "ATTESTATION_TRUST_POLICY"


class AttestationError(ValueError):
    def __init__(self, code: AttestationErrorCode, detail: str):
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or "=" in value
        or len(value) % 4 == 1
        or BASE64URL.fullmatch(value) is None
    ):
        raise AttestationError(
            AttestationErrorCode.MALFORMED_JWS, "non-canonical base64url"
        )
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise AttestationError(
            AttestationErrorCode.MALFORMED_JWS, "invalid base64url"
        ) from exc
    if _b64url(decoded) != value:
        raise AttestationError(
            AttestationErrorCode.MALFORMED_JWS, "non-canonical base64url"
        )
    return decoded


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
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise AttestationError(
                AttestationErrorCode.UNSUPPORTED_VALUE, "invalid Unicode scalar"
            ) from exc
    if isinstance(value, bool):
        return
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


@dataclass(frozen=True)
class TrustEntry:
    issuer: str
    kid: str
    public_key: Ed25519PublicKey
    subjects: frozenset[str]
    not_before: int = 0
    not_after: int = MAX_SAFE_INTEGER
    enabled: bool = True


class TrustStore:
    def __init__(self, entries: list[TrustEntry]):
        self._entries = {(item.issuer, item.kid): item for item in entries}

    def lookup(self, issuer: str, kid: str, subject: str, now: int) -> TrustEntry:
        try:
            entry = self._entries[(issuer, kid)]
        except KeyError as exc:
            raise AttestationError(AttestationErrorCode.UNKNOWN_KEY, kid) from exc
        if (
            not entry.enabled
            or subject not in entry.subjects
            or now < entry.not_before
            or now > entry.not_after
        ):
            raise AttestationError(
                AttestationErrorCode.TRUST_POLICY, f"{issuer}/{kid}/{subject}"
            )
        return entry


def _invalid(detail: str) -> None:
    raise AttestationError(AttestationErrorCode.INVALID_STATEMENT, detail)


def validate_statement(value: dict[str, Any]) -> AttestationStatement:
    top_fields = set(AttestationStatement.__dataclass_fields__)
    process_fields = {"host", "role", "ordinal", "start_identity", "epoch"}
    if set(value) != top_fields:
        _invalid("missing or additional statement property")
    process = value.get("process")
    if not isinstance(process, dict) or set(process) != process_fields:
        _invalid("missing or additional process property")
    string_fields = top_fields - {
        "process",
        "observed_at",
        "issued_at",
        "expires_at",
        "critical_claims",
    }
    for name in string_fields:
        if not isinstance(value[name], str) or not value[name]:
            _invalid(f"{name} must be a non-empty string")
    for name in ("host", "role", "start_identity"):
        if not isinstance(process[name], str) or not process[name]:
            _invalid(f"process.{name} must be a non-empty string")
    for name in ("ordinal", "epoch"):
        item = process[name]
        if (
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 <= item <= MAX_SAFE_INTEGER
        ):
            _invalid(f"process.{name} must be a non-negative safe integer")
    for name in ("observed_at", "issued_at", "expires_at"):
        item = value[name]
        if (
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 <= item <= MAX_SAFE_INTEGER
        ):
            _invalid(f"{name} must be a non-negative safe integer")
    critical = value["critical_claims"]
    if not isinstance(critical, list) or any(not isinstance(x, str) for x in critical):
        _invalid("critical_claims must be an array of strings")
    if len(critical) != len(set(critical)):
        _invalid("critical_claims must be unique")
    if (
        DIGEST.fullmatch(value["artifact_digest"]) is None
        or DIGEST.fullmatch(value["evidence_digest"]) is None
    ):
        _invalid("digest must be sha256:<64 lowercase hex>")
    try:
        return AttestationStatement.from_dict(value)
    except (TypeError, ValueError, KeyError) as exc:
        raise AttestationError(
            AttestationErrorCode.INVALID_STATEMENT, str(exc)
        ) from exc


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
    value = statement.to_dict()
    validate_statement(value)
    payload = canonicalize(value)
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
    max_ttl: int = DEFAULT_MAX_TTL,
    max_observation_age: int = DEFAULT_MAX_OBSERVATION_AGE,
) -> AttestationStatement:
    parts = envelope.detached_jws.split(".")
    if len(parts) != 3 or parts[1] != "":
        raise AttestationError(
            AttestationErrorCode.MALFORMED_JWS, "expected detached compact JWS"
        )
    header_raw = _b64url_decode(parts[0])
    header = parse_strict(header_raw)
    if set(header) != {"alg", "crit", "ecpa_profile", "kid", "typ"}:
        raise AttestationError(
            AttestationErrorCode.UNKNOWN_CRITICAL_HEADER,
            "protected header fields do not match profile",
        )
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
    critical = header.get("crit")
    if critical != ["ecpa_profile"] or "ecpa_profile" not in header:
        raise AttestationError(
            AttestationErrorCode.UNKNOWN_CRITICAL_HEADER, str(critical)
        )
    if header.get("ecpa_profile") != PROFILE:
        raise AttestationError(
            AttestationErrorCode.WRONG_PROFILE, str(header.get("ecpa_profile"))
        )
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise AttestationError(AttestationErrorCode.UNKNOWN_KEY, str(kid))
    payload_value = parse_strict(envelope.payload)
    if envelope.payload != canonicalize(payload_value):
        raise AttestationError(
            AttestationErrorCode.NONCANONICAL_PAYLOAD, "payload must be JCS bytes"
        )
    statement = validate_statement(payload_value)
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
        entry = trust_store.lookup(statement.issuer, kid, statement.subject, now)
        entry.public_key.verify(_b64url_decode(parts[2]), signing_input)
    except InvalidSignature as exc:
        raise AttestationError(AttestationErrorCode.INVALID_SIGNATURE, kid) from exc
    if (
        statement.issued_at > now + clock_skew
        or statement.observed_at > now + clock_skew
    ):
        raise AttestationError(AttestationErrorCode.NOT_YET_VALID, statement.kid)
    if statement.expires_at < now - clock_skew:
        raise AttestationError(AttestationErrorCode.EXPIRED, statement.kid)
    if not statement.observed_at <= statement.issued_at <= statement.expires_at:
        raise AttestationError(
            AttestationErrorCode.INVALID_TIME, "expected observed <= issued <= expires"
        )
    if statement.expires_at - statement.issued_at > max_ttl:
        raise AttestationError(AttestationErrorCode.INVALID_TIME, "TTL exceeds policy")
    if now - statement.observed_at > max_observation_age + clock_skew:
        raise AttestationError(
            AttestationErrorCode.INVALID_TIME, "observation exceeds maximum age"
        )
    return statement


class SignedAttestationVerifier:
    """Adapter for coordinator verification; coordinator retains policy authority."""

    def __init__(
        self,
        envelopes: dict[str, SignedEnvelope],
        trust_store: TrustStore,
        clock_skew: int = 0,
        max_ttl: int = DEFAULT_MAX_TTL,
        max_observation_age: int = DEFAULT_MAX_OBSERVATION_AGE,
    ):
        self.envelopes = envelopes
        self.trust_store = trust_store
        self.clock_skew = clock_skew
        self.max_ttl = max_ttl
        self.max_observation_age = max_observation_age

    def verify(self, attestation: Any, now: int, plan: Any) -> None:
        try:
            envelope = self.envelopes[attestation.nonce]
        except KeyError as exc:
            raise AttestationError(
                AttestationErrorCode.BINDING_MISMATCH, "missing signed envelope"
            ) from exc
        statement = verify(
            envelope,
            self.trust_store,
            now,
            self.clock_skew,
            self.max_ttl,
            self.max_observation_age,
        )
        plugin = next(
            (item for item in plan.plugins if item.id == attestation.artifact_id), None
        )
        expected_digest = None if plugin is None else f"sha256:{plugin.artifact_sha256}"
        if expected_digest is None or statement.artifact_digest != expected_digest:
            raise AttestationError(
                AttestationErrorCode.BINDING_MISMATCH,
                "statement does not bind the expected artifact digest",
            )
        expected = {
            "subject": attestation.authority,
            "issuer": attestation.issuer,
            "kid": attestation.kid,
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
            "observed_at": attestation.observed_at,
            "expires_at": attestation.expires_at,
            "challenge_nonce": attestation.nonce,
            "evidence_digest": attestation.evidence_digest,
            "artifact_digest": attestation.artifact_digest,
        }
        actual = {
            "subject": statement.subject,
            "issuer": statement.issuer,
            "kid": statement.kid,
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
            "observed_at": statement.observed_at,
            "expires_at": statement.expires_at,
            "challenge_nonce": statement.challenge_nonce,
            "evidence_digest": statement.evidence_digest,
            "artifact_digest": statement.artifact_digest,
        }
        if actual != expected:
            raise AttestationError(
                AttestationErrorCode.BINDING_MISMATCH, "statement does not bind receipt"
            )
