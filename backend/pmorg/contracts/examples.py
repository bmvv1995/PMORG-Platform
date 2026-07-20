"""Deterministic synthetic examples for every registered contract."""

from __future__ import annotations

import types as python_types
from datetime import datetime
from typing import Annotated
from typing import Any
from typing import get_args
from typing import get_origin
from typing import Literal
from typing import Union
from uuid import UUID

from pydantic import AwareDatetime
from pydantic import BaseModel

_DIGEST = "sha256:" + "0" * 64
_HMAC_DIGEST = "hmac-sha256:" + "0" * 64
_GIT_SHA = "0" * 40
_UUID7 = "01900000-0000-7000-8000-000000000001"
_UTC_TIME = "2026-01-01T00:00:00Z"


def _string_example(field_name: str, metadata: list[Any]) -> str:
    if field_name == "schema_version":
        return "pmorg.qualification-report/v1"
    if field_name.endswith("_hmac") or "uid_hmac" in field_name:
        return _HMAC_DIGEST
    if (
        field_name.endswith("_hash")
        or field_name.endswith("_digest")
        or field_name.endswith("_fingerprint")
        or field_name in {"digest", "content_hash", "input_hash", "signal_hash"}
    ):
        return _DIGEST
    if field_name == "sig":
        return "c2ln"
    if field_name == "payload":
        return "e30="
    if field_name == "payloadType":
        return "application/vnd.pmorg.contract+json"
    if field_name.endswith("_commit") or field_name == "commit":
        return _GIT_SHA
    if field_name in {"repository", "pmorg_repository", "upstream_repository"}:
        return "https://github.com/example/repository.git"
    if field_name in {"relative_path", "path", "subject_path", "upstream_ee_path"}:
        return "evidence/example.json"
    if field_name in {"media_type"}:
        return "application/json"
    if field_name.endswith("_version") or field_name == "catalog_version":
        return "1.0.0"
    for constraint in metadata:
        pattern = getattr(constraint, "pattern", None)
        if pattern and pattern.startswith("^sha256:"):
            return _DIGEST
        if pattern and pattern.startswith("^hmac-sha256:"):
            return _HMAC_DIGEST
        if pattern and "[0-9a-f]{40}" in pattern:
            return _GIT_SHA
        if pattern and "[0-9]*\\." in pattern:
            return "1.0.0"
    return "example"


def _example_value(*, field_name: str, annotation: Any, metadata: list[Any]) -> Any:
    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is Annotated:
        return _example_value(
            field_name=field_name,
            annotation=arguments[0],
            metadata=[*metadata, *arguments[1:]],
        )
    if origin is Literal:
        return arguments[0]
    if origin in {Union, python_types.UnionType}:
        if type(None) in arguments:
            return None
        return _example_value(
            field_name=field_name,
            annotation=arguments[0],
            metadata=[],
        )
    if origin is list:
        return [
            _example_value(
                field_name=field_name.removesuffix("s"),
                annotation=arguments[0],
                metadata=[],
            )
        ]
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return example_for_model(annotation)
    if annotation is UUID:
        return _UUID7
    if annotation in {datetime, AwareDatetime}:
        return _UTC_TIME
    if annotation is str:
        return _string_example(field_name, metadata)
    if annotation is int:
        return 1
    if annotation is float:
        return 0.5
    if annotation is bool:
        return True
    raise TypeError(f"no deterministic example rule for {field_name}: {annotation!r}")


def example_for_model(model: type[BaseModel]) -> dict[str, Any]:
    """Build one stable, schema-valid JSON object for a contract model."""

    return {
        field_name: _example_value(
            field_name=field_name,
            annotation=field.annotation,
            metadata=list(field.metadata),
        )
        for field_name, field in model.model_fields.items()
    }
