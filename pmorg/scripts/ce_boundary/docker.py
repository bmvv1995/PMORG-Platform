"""Fail-closed validation of CE Dockerfiles and build contexts."""

from __future__ import annotations

import fnmatch
import json
import re
import shlex
from pathlib import Path
from typing import Iterable
from typing import Iterator
from typing import Sequence

from .models import DockerBuild
from .models import DockerIgnoreRule
from .models import DockerInstruction
from .models import SOURCE_SUFFIXES
from .models import Violation
from .models import _is_denied_repository_path
from .models import _is_under
from .models import _normalize_path
from .models import _relative_to_root

def _iter_dockerfile_instructions(text: str) -> Iterator[DockerInstruction]:
    buffer: list[str] = []
    start_line = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start_line = line_number
        continuation = stripped.endswith("\\")
        buffer.append(stripped[:-1].rstrip() if continuation else stripped)
        if continuation:
            continue
        logical_line = " ".join(buffer)
        buffer.clear()
        parts = logical_line.split(None, 1)
        if not parts:
            continue
        yield DockerInstruction(
            name=parts[0].upper(),
            arguments=parts[1] if len(parts) == 2 else "",
            line=start_line,
        )
    if buffer:
        parts = " ".join(buffer).split(None, 1)
        yield DockerInstruction(
            name=parts[0].upper(),
            arguments=parts[1] if len(parts) == 2 else "",
            line=start_line,
        )


def _parse_copy_sources(arguments: str) -> tuple[list[str], bool]:
    remaining_arguments = arguments.strip()
    has_from = False
    while remaining_arguments.startswith("--"):
        option_match = re.match(r"--([a-z-]+)(?:=([^\s]+))?\s+", remaining_arguments)
        if option_match is None:
            break
        option_name = option_match.group(1)
        option_value = option_match.group(2)
        remaining_arguments = remaining_arguments[option_match.end() :]
        if option_name == "from":
            has_from = True
            if option_value is None:
                _, separator, remaining_arguments = remaining_arguments.partition(" ")
                if not separator:
                    return [], True
    if has_from:
        return [], True
    if remaining_arguments.startswith("["):
        try:
            json_sources = json.loads(remaining_arguments)
        except json.JSONDecodeError:
            return [], False
        if not isinstance(json_sources, list) or not all(
            isinstance(item, str) for item in json_sources
        ):
            return [], False
        return json_sources[:-1], False

    try:
        tokens = shlex.split(remaining_arguments, posix=True)
    except ValueError:
        return [], False
    if len(tokens) < 2:
        return [], False
    return tokens[:-1], False


def _parse_dockerignore(text: str) -> list[DockerIgnoreRule]:
    rules: list[DockerIgnoreRule] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        negated = stripped.startswith("!")
        if negated:
            stripped = stripped[1:]
        directory_only = stripped.endswith("/")
        normalized = stripped.replace("\\", "/").lstrip("/")
        if directory_only:
            normalized = normalized.rstrip("/")
        rules.append(
            DockerIgnoreRule(
                pattern=normalized,
                negated=negated,
                line=line_number,
                directory_only=directory_only,
            )
        )
    return rules


def _dockerignore_rule_matches(rule: DockerIgnoreRule, target: str) -> bool:
    normalized_target = _normalize_path(target)
    pattern = _normalize_path(rule.pattern)
    if not pattern:
        return False
    if rule.directory_only:
        return _is_under(normalized_target, pattern) or any(
            _is_under("/".join(normalized_target.split("/")[index:]), pattern)
            for index in range(1, len(normalized_target.split("/")))
        )
    if "/" not in pattern:
        return any(
            fnmatch.fnmatchcase(component, pattern)
            for component in normalized_target.split("/")
        )
    return fnmatch.fnmatchcase(normalized_target, pattern) or (
        not any(character in pattern for character in "*?[")
        and _is_under(normalized_target, pattern)
    )


def _dockerignore_ignores(rules: Sequence[DockerIgnoreRule], target: str) -> bool:
    ignored = False
    for rule in rules:
        if _dockerignore_rule_matches(rule, target):
            ignored = not rule.negated
    return ignored


def _context_relative_prefix(
    repository_prefix: str, context: Path, repository_root: Path
) -> str | None:
    absolute_prefix = repository_root / repository_prefix
    try:
        return absolute_prefix.resolve().relative_to(context.resolve()).as_posix()
    except ValueError:
        return None


def _required_dockerignore_targets(
    build: DockerBuild,
    repository_root: Path,
    denied_prefixes: Sequence[str],
    forbidden_dependency_inputs: Sequence[str],
) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for prefix in denied_prefixes:
        relative_prefix = _context_relative_prefix(
            prefix, build.context, repository_root
        )
        if relative_prefix is not None:
            targets.append((prefix, f"{relative_prefix}/__pmorg_ce_probe__"))
    for dependency_input in forbidden_dependency_inputs:
        relative_path = _context_relative_prefix(
            dependency_input, build.context, repository_root
        )
        if relative_path is not None:
            targets.append((dependency_input, relative_path))
    return targets


def _copy_source_targets_denied(
    source: str,
    build: DockerBuild,
    repository_root: Path,
    denied_prefixes: Sequence[str],
) -> bool:
    normalized_source = _normalize_path(source)
    if not normalized_source or normalized_source == "-":
        return False
    source_without_glob = re.split(r"[*?[]", normalized_source, maxsplit=1)[0]
    absolute_source = build.context / source_without_glob
    repository_path = _relative_to_root(absolute_source, repository_root)
    if repository_path is None:
        return True
    return any(
        _is_under(repository_path, prefix)
        for prefix in denied_prefixes
        if source_without_glob
    )


def _expand_local_copy_source(
    source: str,
    build: DockerBuild,
    ignore_rules: Sequence[DockerIgnoreRule],
    repository_root: Path,
    denied_prefixes: Sequence[str],
) -> tuple[set[Path], list[Violation]]:
    files: set[Path] = set()
    violations: list[Violation] = []
    normalized_source = _normalize_path(source)
    if normalized_source in {"", "."}:
        matches = [build.context]
    elif any(character in normalized_source for character in "*?["):
        matches = list(build.context.glob(normalized_source))
    else:
        matches = [build.context / normalized_source]

    for match in matches:
        try:
            match.resolve().relative_to(build.context.resolve())
        except ValueError:
            violations.append(
                Violation(
                    "DOCKERFILE_CONTEXT_ESCAPE",
                    str(build.dockerfile),
                    0,
                    f"local COPY source escapes build context: {source!r}",
                )
            )
            continue
        if not match.exists() and not match.is_symlink():
            violations.append(
                Violation(
                    "DOCKERFILE_SOURCE_MISSING",
                    str(build.dockerfile),
                    0,
                    f"local COPY source does not exist: {source!r}",
                )
            )
            continue
        candidates: Iterable[Path]
        if match.is_dir() and not match.is_symlink():
            candidates = (
                candidate
                for candidate in match.rglob("*")
                if candidate.is_file() or candidate.is_symlink()
            )
        else:
            candidates = (match,)
        for candidate in candidates:
            context_path = candidate.relative_to(build.context).as_posix()
            if _dockerignore_ignores(ignore_rules, context_path):
                continue
            if candidate.is_symlink():
                resolved = candidate.resolve()
                repository_path = _relative_to_root(resolved, repository_root)
                if repository_path is None or _is_denied_repository_path(
                    repository_path, denied_prefixes
                ):
                    violations.append(
                        Violation(
                            "DELIVERABLE_EE_SYMLINK",
                            context_path,
                            0,
                            "symlink resolves outside the allowed CE source "
                            f"graph: {resolved}",
                        )
                    )
                continue
            repository_path = _relative_to_root(candidate, repository_root)
            if repository_path is None:
                continue
            if _is_denied_repository_path(repository_path, denied_prefixes):
                violations.append(
                    Violation(
                        "DELIVERABLE_EE_PATH",
                        repository_path,
                        0,
                        "Docker build includes a forbidden EE source path",
                    )
                )
                continue
            if candidate.suffix.lower() in SOURCE_SUFFIXES:
                files.add(candidate)
    return files, violations


def validate_docker_build(
    build: DockerBuild,
    repository_root: Path,
    denied_prefixes: Sequence[str],
    forbidden_dependency_inputs: Sequence[str],
) -> tuple[set[Path], list[Violation]]:
    violations: list[Violation] = []
    sources: set[Path] = set()
    dockerfile_display = _relative_to_root(build.dockerfile, repository_root) or str(
        build.dockerfile
    )
    dockerignore_display = _relative_to_root(
        build.dockerignore, repository_root
    ) or str(build.dockerignore)

    if not build.dockerfile.is_file():
        return sources, [
            Violation(
                "DOCKERFILE_MISSING",
                dockerfile_display,
                0,
                "dedicated CE Dockerfile does not exist",
            )
        ]
    if not build.dockerignore.is_file():
        return sources, [
            Violation(
                "DOCKERIGNORE_MISSING",
                dockerignore_display,
                0,
                "dedicated Docker ignore file does not exist",
            )
        ]
    if build.dockerignore.name == ".dockerignore":
        violations.append(
            Violation(
                "DOCKERIGNORE_NOT_DEDICATED",
                dockerignore_display,
                0,
                "CE build must use a Dockerfile-specific ignore file",
            )
        )

    try:
        dockerfile_text = build.dockerfile.read_text(encoding="utf-8")
        dockerignore_text = build.dockerignore.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return sources, [
            Violation(
                "BUILD_INPUT_READ_ERROR",
                dockerfile_display,
                0,
                str(error),
            )
        ]

    ignore_rules = _parse_dockerignore(dockerignore_text)
    required_targets = _required_dockerignore_targets(
        build,
        repository_root,
        denied_prefixes,
        forbidden_dependency_inputs,
    )
    for policy_path, probe_path in required_targets:
        if not _dockerignore_ignores(ignore_rules, probe_path):
            violations.append(
                Violation(
                    "DOCKERIGNORE_MISSING_DENY",
                    dockerignore_display,
                    0,
                    f"does not exclude {policy_path!r} from the build context",
                )
            )
    denied_context_prefixes = {
        context_prefix
        for policy_prefix in denied_prefixes
        if (
            context_prefix := _context_relative_prefix(
                policy_prefix, build.context, repository_root
            )
        )
        is not None
    }
    for rule in ignore_rules:
        if not rule.negated:
            continue
        normalized_pattern = _normalize_path(rule.pattern)
        literal_prefix = re.split(r"[*?[]", normalized_pattern, maxsplit=1)[0].rstrip(
            "/"
        )
        if any(
            _is_under(literal_prefix, denied_prefix)
            or _is_under(denied_prefix, literal_prefix)
            for denied_prefix in denied_context_prefixes
            if literal_prefix
        ):
            violations.append(
                Violation(
                    "DOCKERIGNORE_REINCLUDES_DENIED",
                    dockerignore_display,
                    rule.line,
                    f"negation may re-include forbidden path: !{rule.pattern}",
                )
            )

    dependency_selection_seen = False
    python_dependency_management_seen = False
    for instruction in _iter_dockerfile_instructions(dockerfile_text):
        lower_arguments = instruction.arguments.lower()
        if instruction.name in {"COPY", "ADD", "RUN"}:
            forbidden_fragments = (
                "requirements/ee.txt",
                "requirements/combined.txt",
                "ee-requirements",
            )
            if any(fragment in lower_arguments for fragment in forbidden_fragments):
                violations.append(
                    Violation(
                        "DOCKERFILE_EE_DEPENDENCY",
                        dockerfile_display,
                        instruction.line,
                        "instruction references an EE or combined dependency export",
                    )
                )
            if re.search(r"--(?:only-)?group(?:=|\s+)ee(?:\s|$)", lower_arguments):
                violations.append(
                    Violation(
                        "DOCKERFILE_EE_DEPENDENCY",
                        dockerfile_display,
                        instruction.line,
                        "instruction selects the uv EE dependency group",
                    )
                )
            if any(
                marker in lower_arguments
                for marker in (
                    "requirements/",
                    "uv pip",
                    "uv sync",
                    "uv export",
                    "pip install",
                )
            ):
                python_dependency_management_seen = True
        if instruction.name == "RUN" and "uv sync" in lower_arguments:
            if "--no-default-groups" not in lower_arguments:
                violations.append(
                    Violation(
                        "DOCKERFILE_UV_DEFAULT_GROUPS",
                        dockerfile_display,
                        instruction.line,
                        "uv sync must disable default groups in a CE build",
                    )
                )
            if (
                "--group backend" in lower_arguments
                or "--group=backend" in lower_arguments
            ):
                dependency_selection_seen = True
        if instruction.name == "RUN" and "uv export" in lower_arguments:
            if "--no-default-groups" not in lower_arguments:
                violations.append(
                    Violation(
                        "DOCKERFILE_UV_DEFAULT_GROUPS",
                        dockerfile_display,
                        instruction.line,
                        "uv export must disable default groups in a CE build",
                    )
                )
        if "requirements/default.txt" in lower_arguments or (
            "requirements.txt" in lower_arguments
            and "ee-requirements" not in lower_arguments
        ):
            dependency_selection_seen = True

        if instruction.name not in {"COPY", "ADD"}:
            continue
        copy_sources, copied_from_stage = _parse_copy_sources(instruction.arguments)
        if copied_from_stage:
            continue
        for copy_source in copy_sources:
            if _copy_source_targets_denied(
                copy_source, build, repository_root, denied_prefixes
            ):
                violations.append(
                    Violation(
                        "DOCKERFILE_EE_SOURCE",
                        dockerfile_display,
                        instruction.line,
                        "local build source overlaps a forbidden EE path: "
                        f"{copy_source!r}",
                    )
                )
            expanded_sources, expansion_violations = _expand_local_copy_source(
                copy_source,
                build,
                ignore_rules,
                repository_root,
                denied_prefixes,
            )
            sources.update(expanded_sources)
            violations.extend(
                Violation(
                    violation.rule,
                    violation.path,
                    instruction.line if violation.line == 0 else violation.line,
                    violation.message,
                )
                for violation in expansion_violations
            )

    context_repository_path = _relative_to_root(build.context, repository_root)
    requires_python_dependency_proof = (
        context_repository_path == "backend" or python_dependency_management_seen
    )
    if requires_python_dependency_proof and not dependency_selection_seen:
        violations.append(
            Violation(
                "DOCKERFILE_DEPENDENCY_SELECTION_MISSING",
                dockerfile_display,
                0,
                "cannot prove that the build selects only CE backend dependencies",
            )
        )
    return sources, violations
