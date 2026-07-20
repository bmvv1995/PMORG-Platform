"""Emit and verify development-test RBDP DSSE envelopes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from jsonschema import Draft202012Validator

from pmorg.contracts.types import DsseEnvelope
from pmorg.contracts.types import DsseSignature
from pmorg.contracts.types import ReleaseBuildDefinitionPayload

RBDP_PAYLOAD_TYPE = "application/vnd.pmorg.release-build-definition.v1+json"
RBDP_SCHEMA_VERSION = "pmorg.release-build-definition/v1"
PRIVATE_KEY_ENV = "PMORG_RBDP_TEST_ED25519_PRIVATE_KEY"
PUBLIC_KEY_ENV = "PMORG_RBDP_TEST_ED25519_PUBLIC_KEY"


class RbdpVerificationError(ValueError):
    """Raised when an RBDP envelope or committed contract binding is invalid."""


def canonical_json_bytes(value: Any) -> bytes:
    """Encode one unambiguous JSON value for signing."""

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def pre_authentication_encoding(payload_type: str, payload: bytes) -> bytes:
    """Return the DSSE v1 pre-authentication encoding."""

    payload_type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        (
            b"DSSEv1",
            str(len(payload_type_bytes)).encode("ascii"),
            payload_type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        )
    )


def _decode_base64(value: str, *, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise RbdpVerificationError(f"{label} is not canonical base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise RbdpVerificationError(f"{label} is not canonical base64")
    return decoded


def _key_material_from_env(
    name: str,
    *,
    environ: Mapping[str, str] | None,
) -> bytes:
    source = os.environ if environ is None else environ
    encoded = source.get(name)
    if not encoded:
        raise RbdpVerificationError(
            f"required ephemeral key environment is absent: {name}"
        )
    return _decode_base64(encoded, label=name)


def private_key_from_env(
    *,
    name: str = PRIVATE_KEY_ENV,
    environ: Mapping[str, str] | None = None,
) -> Ed25519PrivateKey:
    """Load one raw Ed25519 private key only from an environment mapping."""

    raw_key = _key_material_from_env(name, environ=environ)
    if len(raw_key) != 32:
        raise RbdpVerificationError(f"{name} must contain exactly 32 raw key bytes")
    return Ed25519PrivateKey.from_private_bytes(raw_key)


def public_key_from_env(
    *,
    name: str = PUBLIC_KEY_ENV,
    environ: Mapping[str, str] | None = None,
) -> Ed25519PublicKey:
    """Load one raw Ed25519 public key only from an environment mapping."""

    raw_key = _key_material_from_env(name, environ=environ)
    if len(raw_key) != 32:
        raise RbdpVerificationError(f"{name} must contain exactly 32 raw key bytes")
    return Ed25519PublicKey.from_public_bytes(raw_key)


def export_ephemeral_key_environment(
    private_key: Ed25519PrivateKey,
) -> dict[str, str]:
    """Materialize generated test key bytes for an in-memory environment only."""

    private_bytes = private_key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        PRIVATE_KEY_ENV: base64.b64encode(private_bytes).decode("ascii"),
        PUBLIC_KEY_ENV: base64.b64encode(public_bytes).decode("ascii"),
    }


def key_id(public_key: Ed25519PublicKey) -> str:
    """Derive the stable verification-material identity from the public key."""

    raw_key = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519-sha256:" + hashlib.sha256(raw_key).hexdigest()


def _contract_definition(contract_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        manifest = json.loads((contract_root / "manifest.json").read_bytes())
        entry = next(
            item
            for item in manifest["contracts"]
            if item["schema_version"] == RBDP_SCHEMA_VERSION
        )
        schema_bytes = (contract_root / entry["schema_path"]).read_bytes()
        schema = json.loads(schema_bytes)
    except (
        FileNotFoundError,
        KeyError,
        StopIteration,
        TypeError,
        json.JSONDecodeError,
    ) as error:
        raise RbdpVerificationError(
            "committed RBDP contract artifacts are incomplete"
        ) from error
    actual_digest = "sha256:" + hashlib.sha256(schema_bytes).hexdigest()
    if actual_digest != entry.get("schema_sha256"):
        raise RbdpVerificationError(
            "committed RBDP schema digest does not match manifest"
        )
    if manifest.get("wire_surface") != "pmorg-contracts/1.0":
        raise RbdpVerificationError("RBDP contract manifest has the wrong wire surface")
    return manifest, schema


def _validate_payload_contract(
    payload: ReleaseBuildDefinitionPayload,
    *,
    contract_root: Path,
) -> None:
    manifest, schema = _contract_definition(contract_root)
    if payload.pmorg_spec_commit != manifest["specification"]["commit"]:
        raise RbdpVerificationError(
            "RBDP does not pin the committed PMORG specification"
        )
    if payload.onyx_surface != "ce":
        raise RbdpVerificationError("this RBDP emitter admits only the CE surface")
    if payload.allowed_usage_modes != ["development_test"]:
        raise RbdpVerificationError("RBDP usage must be exactly development_test")
    try:
        Draft202012Validator(schema).validate(payload.model_dump(mode="json"))
    except Exception as error:
        raise RbdpVerificationError(
            "RBDP does not validate against its committed schema"
        ) from error


def sign_release_build_definition(
    payload: ReleaseBuildDefinitionPayload | Mapping[str, Any],
    *,
    contract_root: Path,
    environ: Mapping[str, str] | None = None,
) -> DsseEnvelope:
    """Create a single-signature RBDP envelope with an ephemeral environment key."""

    validated = ReleaseBuildDefinitionPayload.model_validate(payload)
    _validate_payload_contract(validated, contract_root=contract_root)
    payload_bytes = canonical_json_bytes(validated.model_dump(mode="json"))
    private_key = private_key_from_env(environ=environ)
    signature = private_key.sign(
        pre_authentication_encoding(RBDP_PAYLOAD_TYPE, payload_bytes)
    )
    return DsseEnvelope(
        payloadType=RBDP_PAYLOAD_TYPE,
        payload=base64.b64encode(payload_bytes).decode("ascii"),
        signatures=[
            DsseSignature(
                keyid=key_id(private_key.public_key()),
                sig=base64.b64encode(signature).decode("ascii"),
            )
        ],
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RbdpVerificationError(f"RBDP payload repeats JSON key: {key}")
        value[key] = item
    return value


def verify_release_build_definition(
    envelope: DsseEnvelope | Mapping[str, Any],
    *,
    contract_root: Path,
    environ: Mapping[str, str] | None = None,
) -> ReleaseBuildDefinitionPayload:
    """Verify DSSE identity, signature, canonical payload, model, and schema binding."""

    validated_envelope = DsseEnvelope.model_validate(envelope)
    if validated_envelope.payloadType != RBDP_PAYLOAD_TYPE:
        raise RbdpVerificationError("unexpected RBDP DSSE payload type")
    if len(validated_envelope.signatures) != 1:
        raise RbdpVerificationError("RBDP requires exactly one DSSE signature")
    payload_bytes = _decode_base64(validated_envelope.payload, label="DSSE payload")
    signature_record = validated_envelope.signatures[0]
    signature = _decode_base64(signature_record.sig, label="DSSE signature")
    public_key = public_key_from_env(environ=environ)
    if signature_record.keyid != key_id(public_key):
        raise RbdpVerificationError(
            "DSSE key identity does not match verification material"
        )
    try:
        public_key.verify(
            signature,
            pre_authentication_encoding(validated_envelope.payloadType, payload_bytes),
        )
    except InvalidSignature as error:
        raise RbdpVerificationError("RBDP DSSE signature is invalid") from error
    try:
        decoded_payload = json.loads(
            payload_bytes,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RbdpVerificationError("RBDP DSSE payload is not valid JSON") from error
    if canonical_json_bytes(decoded_payload) != payload_bytes:
        raise RbdpVerificationError("RBDP DSSE payload is not canonical JSON")
    payload = ReleaseBuildDefinitionPayload.model_validate_json(payload_bytes)
    _validate_payload_contract(payload, contract_root=contract_root)
    return payload


__all__ = [
    "PRIVATE_KEY_ENV",
    "PUBLIC_KEY_ENV",
    "RBDP_PAYLOAD_TYPE",
    "RbdpVerificationError",
    "canonical_json_bytes",
    "export_ephemeral_key_environment",
    "key_id",
    "pre_authentication_encoding",
    "private_key_from_env",
    "public_key_from_env",
    "sign_release_build_definition",
    "verify_release_build_definition",
]
