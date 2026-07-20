"""Fail-closed AST guard for the pure legacy compatibility package."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath

ALLOWED_IMPORT_ROOTS = frozenset(
    {
        "__future__",
        "collections",
        "hashlib",
        "json",
        "pmorg",
        "pydantic",
        "typing",
        "uuid",
    }
)
FORBIDDEN_CALL_NAMES = frozenset(
    {
        "open",
        "read_bytes",
        "read_text",
        "request",
        "urlopen",
        "write_bytes",
        "write_text",
    }
)


@dataclass(frozen=True, order=True)
class LegacyPurityViolation:
    relative_path: PurePosixPath
    line_number: int
    detail: str


class LegacyPurityError(ValueError):
    """Raised when the compatibility mapper gains an I/O dependency."""


def find_legacy_purity_violations(
    legacy_root: Path,
) -> tuple[LegacyPurityViolation, ...]:
    if not legacy_root.is_dir():
        raise FileNotFoundError(
            f"legacy compatibility root does not exist: {legacy_root}"
        )
    backend_root = legacy_root.parents[2]
    violations: list[LegacyPurityViolation] = []
    for source_path in sorted(legacy_root.rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), source_path)
        relative_path = PurePosixPath(source_path.relative_to(backend_root).as_posix())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.partition(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").partition(".")[0]]
            else:
                roots = []
            for root in roots:
                if root and root not in ALLOWED_IMPORT_ROOTS:
                    violations.append(
                        LegacyPurityViolation(
                            relative_path,
                            getattr(node, "lineno", 0),
                            f"forbidden import root {root}",
                        )
                    )
            if isinstance(node, ast.Call):
                function_name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
                if function_name in FORBIDDEN_CALL_NAMES:
                    violations.append(
                        LegacyPurityViolation(
                            relative_path,
                            node.lineno,
                            f"forbidden I/O call {function_name}",
                        )
                    )
    return tuple(sorted(violations))


def assert_legacy_mapper_purity(legacy_root: Path) -> None:
    violations = find_legacy_purity_violations(legacy_root)
    if not violations:
        return
    details = "\n".join(
        f"{item.relative_path}:{item.line_number}: {item.detail}" for item in violations
    )
    raise LegacyPurityError(f"legacy mapper purity violations:\n{details}")
