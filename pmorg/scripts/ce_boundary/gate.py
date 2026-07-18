"""Orchestration for source linting and bound-artifact qualification."""

from __future__ import annotations

from pathlib import Path

from .docker import validate_docker_build
from .images import _qualify_artifacts
from .models import GateConfig
from .models import GateReport
from .models import QualificationIdentity
from .models import QualifiedImage
from .models import Violation
from .source import _expand_explicit_source
from .source import scan_source_file

def run_gate(config: GateConfig) -> GateReport:
    repository_root = config.repository_root.resolve()
    source_files: set[Path] = set()
    violations: list[Violation] = []

    for build in config.builds:
        build_sources, build_violations = validate_docker_build(
            build,
            repository_root,
            config.denied_source_prefixes,
            config.forbidden_dependency_inputs,
        )
        source_files.update(build_sources)
        violations.extend(build_violations)
    for source_path in config.source_paths:
        explicit_sources, source_violations = _expand_explicit_source(
            source_path, repository_root, config.denied_source_prefixes
        )
        source_files.update(explicit_sources)
        violations.extend(source_violations)

    for source_file in sorted(source_files):
        violations.extend(
            scan_source_file(
                source_file, repository_root, config.denied_source_prefixes
            )
        )
    dependency_verified = False
    qualified_images: tuple[QualifiedImage, ...] = ()
    inspected_artifact_entries = 0
    qualification_identity: QualificationIdentity | None = None
    if config.mode == "qualify":
        (
            dependency_verified,
            qualified_images,
            inspected_artifact_entries,
            qualification_identity,
            qualification_violations,
        ) = _qualify_artifacts(config)
        violations.extend(qualification_violations)
    elif config.mode != "source":
        violations.append(
            Violation(
                "GATE_MODE_INVALID",
                config.mode,
                0,
                "mode must be 'source' or 'qualify'",
            )
        )

    unique_violations = tuple(sorted(set(violations)))
    return GateReport(
        mode=config.mode,
        scanned_source_files=len(source_files),
        inspected_artifact_entries=inspected_artifact_entries,
        dependency_evidence_verified=dependency_verified,
        qualified_images=qualified_images,
        source_revision=(
            qualification_identity.source_revision
            if qualification_identity is not None
            else None
        ),
        baseline_manifest_sha256=(
            qualification_identity.baseline_manifest_sha256
            if qualification_identity is not None
            else None
        ),
        target_platform=(
            qualification_identity.target_platform
            if qualification_identity is not None
            else None
        ),
        violations=unique_violations,
    )
