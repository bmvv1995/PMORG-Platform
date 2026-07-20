from __future__ import annotations

import fnmatch
import importlib
import json
import unittest
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = Path(__file__).resolve().parent
SEAM_ALLOWLIST_PATH = REPOSITORY_ROOT / "pmorg/policies/seam-allowlist.json"
SEAM_PROTECTOR_PATTERN = "test_*_seam_protector.py"
DEFAULT_DISCOVERY_PATTERN = "test_*.py"
TEST_MODULE_PREFIX = "pmorg.tests"


@dataclass(frozen=True)
class ActiveSuitePlan:
    all_modules: tuple[str, ...]
    active_protectors: tuple[str, ...]
    retired_protectors: tuple[str, ...]
    included_modules: tuple[str, ...]


def _module_name(path: Path) -> str:
    return f"{TEST_MODULE_PREFIX}.{path.stem}"


def _active_protector_filenames(policy_path: Path) -> set[str]:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    seams = policy.get("seams")
    if not isinstance(seams, list):
        raise ValueError("seam allowlist must contain a seams array")

    filenames: set[str] = set()
    for seam in seams:
        if not isinstance(seam, dict):
            raise ValueError("every active seam must be an object")
        selectors = seam.get("required_protector_tests")
        if not isinstance(selectors, list):
            raise ValueError("every active seam must list required protector tests")
        for selector in selectors:
            if not isinstance(selector, str) or "::" not in selector:
                raise ValueError("protector selectors must be path::selector strings")
            protector_path = PurePosixPath(selector.split("::", 1)[0])
            if protector_path.parent == PurePosixPath(
                "pmorg/tests"
            ) and fnmatch.fnmatchcase(protector_path.name, SEAM_PROTECTOR_PATTERN):
                filenames.add(protector_path.name)
    return filenames


def active_suite_plan(
    *,
    pattern: str = DEFAULT_DISCOVERY_PATTERN,
    tests_dir: Path = TESTS_DIR,
    policy_path: Path = SEAM_ALLOWLIST_PATH,
) -> ActiveSuitePlan:
    all_test_paths = tuple(sorted(tests_dir.glob(pattern)))
    all_modules = tuple(_module_name(path) for path in all_test_paths)

    protector_paths = tuple(sorted(tests_dir.glob(SEAM_PROTECTOR_PATTERN)))
    protector_filenames = {path.name for path in protector_paths}
    active_filenames = _active_protector_filenames(policy_path)
    missing_active = active_filenames - protector_filenames
    if missing_active:
        raise ValueError(
            "active CI protector modules are missing: "
            + ", ".join(sorted(missing_active))
        )

    active_protectors = tuple(
        _module_name(path) for path in protector_paths if path.name in active_filenames
    )
    retired_protectors = tuple(
        _module_name(path)
        for path in protector_paths
        if path.name not in active_filenames
    )
    retired_set = set(retired_protectors)
    included_modules = tuple(
        module_name for module_name in all_modules if module_name not in retired_set
    )
    return ActiveSuitePlan(
        all_modules=all_modules,
        active_protectors=active_protectors,
        retired_protectors=retired_protectors,
        included_modules=included_modules,
    )


def load_tests(
    loader: unittest.TestLoader,
    standard_tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    plan = active_suite_plan(pattern=pattern or DEFAULT_DISCOVERY_PATTERN)
    suite = loader.suiteClass()
    suite.addTests(standard_tests)
    for module_name in plan.included_modules:
        module = importlib.import_module(module_name)
        suite.addTests(loader.loadTestsFromModule(module))
    return suite
