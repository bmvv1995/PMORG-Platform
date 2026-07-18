"""Command-line interface for the PMORG CE boundary gate."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from .gate import run_gate
from .models import DEFAULT_DENIED_SOURCE_PREFIXES
from .models import DEFAULT_DOCKERFILES
from .models import REPORT_SCHEMA_VERSION
from .models import DockerBuild
from .models import GateConfig
from .models import GateReport

def _resolve_cli_path(repository_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else repository_root / path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the PMORG Community Edition source and artifact boundary."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    source_parser = subparsers.add_parser(
        "source", help="lint CE source and Docker build inputs"
    )
    qualify_parser = subparsers.add_parser(
        "qualify", help="qualify bound backend and web image artifacts"
    )
    for command_parser in (source_parser, qualify_parser):
        _add_source_arguments(command_parser)
    qualify_parser.add_argument(
        "--evidence-manifest",
        required=True,
        help=(
            "JSON manifest binding dependency evidence and exactly the backend "
            "and web image/filesystem artifacts"
        ),
    )
    return parser


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repository-root",
        default=str(Path(__file__).resolve().parents[3]),
        help="repository root (default: inferred from this script)",
    )
    parser.add_argument(
        "--dockerfile",
        action="append",
        default=[],
        help=(
            "dedicated CE Dockerfile; repeat for multiple images "
            f"(default: {', '.join(DEFAULT_DOCKERFILES)})"
        ),
    )
    parser.add_argument(
        "--docker-context",
        action="append",
        default=[],
        help="context matching each --dockerfile (default: Dockerfile parent)",
    )
    parser.add_argument(
        "--dockerignore",
        action="append",
        default=[],
        help=(
            "ignore file matching each --dockerfile "
            "(default: <Dockerfile>.dockerignore)"
        ),
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="additional deliverable source file or directory; repeat as needed",
    )
    parser.add_argument(
        "--deny-source",
        action="append",
        default=[],
        help="additional repository-relative denied source prefix",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable report",
    )


def _config_from_arguments(arguments: argparse.Namespace) -> GateConfig:
    repository_root = Path(arguments.repository_root).resolve()
    dockerfile_values = arguments.dockerfile or list(DEFAULT_DOCKERFILES)
    if arguments.docker_context and len(arguments.docker_context) != len(
        dockerfile_values
    ):
        raise ValueError("--docker-context count must match --dockerfile count")
    if arguments.dockerignore and len(arguments.dockerignore) != len(
        dockerfile_values
    ):
        raise ValueError("--dockerignore count must match --dockerfile count")

    builds: list[DockerBuild] = []
    for index, dockerfile_value in enumerate(dockerfile_values):
        dockerfile = _resolve_cli_path(repository_root, dockerfile_value)
        context = (
            _resolve_cli_path(repository_root, arguments.docker_context[index])
            if arguments.docker_context
            else dockerfile.parent
        )
        dockerignore = (
            _resolve_cli_path(repository_root, arguments.dockerignore[index])
            if arguments.dockerignore
            else Path(str(dockerfile) + ".dockerignore")
        )
        builds.append(
            DockerBuild(
                dockerfile=dockerfile,
                context=context,
                dockerignore=dockerignore,
            )
        )

    return GateConfig(
        repository_root=repository_root,
        builds=tuple(builds),
        mode=arguments.mode,
        source_paths=tuple(
            _resolve_cli_path(repository_root, value) for value in arguments.source
        ),
        evidence_manifest=(
            _resolve_cli_path(repository_root, arguments.evidence_manifest)
            if arguments.mode == "qualify"
            else None
        ),
        denied_source_prefixes=tuple(
            dict.fromkeys((*DEFAULT_DENIED_SOURCE_PREFIXES, *arguments.deny_source))
        ),
    )


def _render_json(report: GateReport) -> str:
    return json.dumps(
        {
            "schema_version": REPORT_SCHEMA_VERSION,
            "mode": report.mode,
            "passed": report.passed,
            "scanned_source_files": report.scanned_source_files,
            "inspected_artifact_entries": report.inspected_artifact_entries,
            "dependency_evidence_verified": (
                report.dependency_evidence_verified
            ),
            "source_revision": report.source_revision,
            "baseline_manifest_sha256": report.baseline_manifest_sha256,
            "target_platform": report.target_platform,
            "qualified_images": [
                asdict(image) for image in report.qualified_images
            ],
            "violations": [asdict(violation) for violation in report.violations],
        },
        indent=2,
        sort_keys=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        config = _config_from_arguments(arguments)
    except ValueError as error:
        parser.error(str(error))
    report = run_gate(config)
    if arguments.json:
        print(_render_json(report))
    elif report.passed:
        print(
            f"PASS: PMORG CE {report.mode} boundary verified "
            f"({report.scanned_source_files} source files, "
            f"{report.inspected_artifact_entries} artifact entries)"
        )
    else:
        print(
            "FAIL: PMORG CE boundary has "
            f"{len(report.violations)} violation(s)",
            file=sys.stderr,
        )
        for violation in report.violations:
            print(f"  {violation.render()}", file=sys.stderr)
    return 0 if report.passed else 1
