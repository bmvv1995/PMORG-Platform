#!/usr/bin/env python3
"""Verify that a PMORG CE build cannot ship or import Onyx EE code.

This module is the stable compatibility facade and CLI entry point. The
implementation lives in the thematic :mod:`ce_boundary` package and uses only
the Python standard library.
"""

from __future__ import annotations

import importlib
import subprocess
import sys


if __package__:
    sys.modules.setdefault(
        "ce_boundary",
        importlib.import_module(f"{__package__}.ce_boundary"),
    )

from ce_boundary.artifacts import _artifact_path_targets_ee
from ce_boundary.artifacts import _artifact_source_size_violation
from ce_boundary.artifacts import _scan_archive_source_bytes
from ce_boundary.artifacts import _scan_tar_members
from ce_boundary.artifacts import scan_filesystem_path
from ce_boundary.cli import _add_source_arguments
from ce_boundary.cli import _build_parser
from ce_boundary.cli import _config_from_arguments
from ce_boundary.cli import _render_json
from ce_boundary.cli import _resolve_cli_path
from ce_boundary.cli import main
from ce_boundary.docker import _context_relative_prefix
from ce_boundary.docker import _copy_source_targets_denied
from ce_boundary.docker import _dockerignore_ignores
from ce_boundary.docker import _dockerignore_rule_matches
from ce_boundary.docker import _expand_local_copy_source
from ce_boundary.docker import _iter_dockerfile_instructions
from ce_boundary.docker import _parse_copy_sources
from ce_boundary.docker import _parse_dockerignore
from ce_boundary.docker import _required_dockerignore_targets
from ce_boundary.docker import validate_docker_build
from ce_boundary.evidence import _command_failure_message
from ce_boundary.evidence import _evidence_path
from ce_boundary.evidence import _required_digest
from ce_boundary.evidence import _required_git_sha
from ce_boundary.evidence import _required_object
from ce_boundary.evidence import _required_string
from ce_boundary.evidence import _sha256_bytes
from ce_boundary.evidence import _sha256_file
from ce_boundary.evidence import _verify_file_digest
from ce_boundary.evidence import load_qualification_evidence
from ce_boundary.evidence import verify_dependency_evidence
from ce_boundary.evidence import verify_qualification_preflight
from ce_boundary.gate import run_gate
from ce_boundary.images import _expected_image_labels
from ce_boundary.images import _qualify_artifacts
from ce_boundary.images import _validate_image_config
from ce_boundary.images import scan_bound_image_archive
from ce_boundary.models import BASELINE_MANIFEST_PATH
from ce_boundary.models import BASELINE_SCHEMA_VERSION
from ce_boundary.models import DEFAULT_DENIED_SOURCE_PREFIXES
from ce_boundary.models import DEFAULT_DOCKERFILES
from ce_boundary.models import DEFAULT_FORBIDDEN_DEPENDENCY_INPUTS
from ce_boundary.models import DEPENDENCY_EVIDENCE_COMMAND
from ce_boundary.models import EVIDENCE_SCHEMA_VERSION
from ce_boundary.models import GIT_SHA_PATTERN
from ce_boundary.models import MAX_ARCHIVE_SOURCE_BYTES
from ce_boundary.models import PYTHON_SUFFIXES
from ce_boundary.models import QUALIFICATION_TARGET_PLATFORM
from ce_boundary.models import QUALIFICATION_UV_IMAGE
from ce_boundary.models import QUALIFICATION_UV_VERSION
from ce_boundary.models import QUALIFIED_IMAGE_NAMES
from ce_boundary.models import REPORT_SCHEMA_VERSION
from ce_boundary.models import SHA256_PATTERN
from ce_boundary.models import SOURCE_SUFFIXES
from ce_boundary.models import TYPESCRIPT_SUFFIXES
from ce_boundary.models import DependencyEvidence
from ce_boundary.models import DockerBuild
from ce_boundary.models import DockerIgnoreRule
from ce_boundary.models import DockerInstruction
from ce_boundary.models import GateConfig
from ce_boundary.models import GateReport
from ce_boundary.models import ImageEvidence
from ce_boundary.models import ImportEdge
from ce_boundary.models import QualificationEvidence
from ce_boundary.models import QualificationIdentity
from ce_boundary.models import QualifiedImage
from ce_boundary.models import Violation
from ce_boundary.models import _JavaScriptToken
from ce_boundary.models import _MutableStats
from ce_boundary.models import _is_denied_repository_path
from ce_boundary.models import _is_under
from ce_boundary.models import _normalize_path
from ce_boundary.models import _relative_to_root
from ce_boundary.source import _constant_python_string
from ce_boundary.source import _expand_explicit_source
from ce_boundary.source import _javascript_import_specifiers
from ce_boundary.source import _javascript_tokens
from ce_boundary.source import _module_targets_ee
from ce_boundary.source import _resolve_typescript_import
from ce_boundary.source import _scan_python_imports
from ce_boundary.source import _scan_typescript_imports
from ce_boundary.source import _typescript_specifier_targets_ee
from ce_boundary.source import scan_source_file


if __name__ == "__main__":
    raise SystemExit(main())
