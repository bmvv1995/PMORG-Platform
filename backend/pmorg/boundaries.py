"""Static dependency checks for the PMORG product boundary."""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath

ALLOWED_DOMAIN_IMPORT_ROOTS = frozenset(sys.stdlib_module_names) | {
    "pydantic",
    "typing_extensions",
}
ALLOWED_PMORG_IMPORT_PREFIXES = (
    "pmorg.contracts",
    "pmorg.domain",
)


@dataclass(frozen=True, order=True)
class DomainImportViolation:
    """One forbidden import found in the PMORG domain layer."""

    relative_path: PurePosixPath
    line_number: int
    imported_module: str


class DomainImportBoundaryError(ValueError):
    """Raised when the PMORG domain depends on an outer layer."""


def _resolve_relative_module(
    *,
    source_path: Path,
    backend_root: Path,
    level: int,
    module: str | None,
) -> str:
    relative_source = source_path.relative_to(backend_root)
    package_parts = list(relative_source.parent.parts)
    parents_to_remove = level - 1
    if parents_to_remove > len(package_parts):
        return "<invalid-relative-import>"
    if parents_to_remove:
        package_parts = package_parts[:-parents_to_remove]
    if module:
        package_parts.extend(module.split("."))
    return ".".join(package_parts)


def _imported_modules(
    *, source_path: Path, backend_root: Path, syntax_tree: ast.AST
) -> Iterator[tuple[int, str]]:
    for node in ast.walk(syntax_tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            imported_from = (
                _resolve_relative_module(
                    source_path=source_path,
                    backend_root=backend_root,
                    level=node.level,
                    module=node.module,
                )
                if node.level
                else node.module or ""
            )
            imports_package_members = node.module is None or imported_from in {
                "backend",
                "pmorg",
            }
            if imports_package_members:
                for alias in node.names:
                    if alias.name != "*" and imported_from:
                        yield node.lineno, f"{imported_from}.{alias.name}"
            elif imported_from:
                yield node.lineno, imported_from


def _is_allowed_domain_import(imported_module: str) -> bool:
    root_module = imported_module.partition(".")[0]
    return root_module in ALLOWED_DOMAIN_IMPORT_ROOTS or any(
        imported_module == prefix or imported_module.startswith(f"{prefix}.")
        for prefix in ALLOWED_PMORG_IMPORT_PREFIXES
    )


def find_domain_import_violations(
    domain_root: Path,
) -> tuple[DomainImportViolation, ...]:
    """Inspect every domain module and return forbidden imports in stable order."""

    if not domain_root.is_dir():
        raise FileNotFoundError(f"PMORG domain root does not exist: {domain_root}")

    backend_root = domain_root.parents[1]
    violations: list[DomainImportViolation] = []
    for source_path in sorted(domain_root.rglob("*.py")):
        source = source_path.read_text(encoding="utf-8")
        syntax_tree = ast.parse(source, filename=str(source_path))
        for line_number, imported_module in _imported_modules(
            source_path=source_path,
            backend_root=backend_root,
            syntax_tree=syntax_tree,
        ):
            if not _is_allowed_domain_import(imported_module):
                violations.append(
                    DomainImportViolation(
                        relative_path=PurePosixPath(
                            source_path.relative_to(backend_root).as_posix()
                        ),
                        line_number=line_number,
                        imported_module=imported_module,
                    )
                )
    return tuple(sorted(violations))


def assert_domain_import_purity(domain_root: Path) -> None:
    """Fail loudly when domain code imports an infrastructure or outer layer."""

    violations = find_domain_import_violations(domain_root)
    if not violations:
        return
    details = "\n".join(
        f"{violation.relative_path}:{violation.line_number}: "
        f"forbidden import {violation.imported_module}"
        for violation in violations
    )
    raise DomainImportBoundaryError(f"PMORG domain boundary violations:\n{details}")
