from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from pmorg.build.artifact import _read_json_object
from pmorg.build.artifact import apply_overlay
from pmorg.build.artifact import build_artifact
from pmorg.build.artifact import EGRESS_PATH
from pmorg.build.artifact import OVERLAY_PATH
from pmorg.build.artifact import REPOSITORY_ROOT
from pmorg.build.artifact import resolve_commit
from pmorg.build.artifact import scan_entries_for_ee
from pmorg.build.artifact import scan_pmorg_worktree
from pmorg.build.artifact import selected_entries
from pmorg.build.artifact import SPEC_PATH
from pmorg.build.artifact import verify_egress


class SyntheticRepository:
    def __init__(self, root: Path) -> None:
        self.root = root

    def write(self, relative: str, content: str | bytes) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    def git(self, *arguments: str) -> None:
        environment = {
            **os.environ,
            "GIT_AUTHOR_NAME": "PMORG Test",
            "GIT_AUTHOR_EMAIL": "pmorg-test@example.invalid",
            "GIT_COMMITTER_NAME": "PMORG Test",
            "GIT_COMMITTER_EMAIL": "pmorg-test@example.invalid",
        }
        subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            check=True,
            capture_output=True,
            env=environment,
        )


class TestCeBuildSubstrate(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory(prefix="pmorg-ce-test-")
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)
        self.repository = SyntheticRepository(self.root)
        self.repository.git("init", "--quiet")

        spec = _read_json_object(SPEC_PATH)
        egress = _read_json_object(EGRESS_PATH)
        ownership = {
            "schema_version": "pmorg.platform.ownership-roots/v2",
            "roots": [
                {
                    "root_id": "pmorg",
                    "path_pattern": "pmorg/**",
                    "ownership": "pmorg_owned",
                },
                {
                    "root_id": "backend-pmorg",
                    "path_pattern": "backend/pmorg/**",
                    "ownership": "pmorg_owned",
                },
            ],
        }
        self.repository.write("pmorg/build/ce-artifact-spec.json", json.dumps(spec))
        self.repository.write("pmorg/build/ce-build-egress.json", json.dumps(egress))
        self.repository.write(
            "pmorg/build/artifact.py",
            (REPOSITORY_ROOT / "pmorg/build/artifact.py").read_bytes(),
        )
        self.repository.write(
            "pmorg/policies/ownership-roots.json",
            json.dumps(ownership),
        )
        community_base = b"VALUE = 'community'\n"
        community_result = b"VALUE = 'ce'\n"
        overlay = {
            "schema_version": "pmorg.ce-source-overlay/v1",
            "entries": [
                {
                    "path": "backend/onyx/community.py",
                    "base_sha256": hashlib.sha256(community_base).hexdigest(),
                    "result_sha256": hashlib.sha256(community_result).hexdigest(),
                    "operations": [
                        {"start": 0, "end": 1, "replacement": "VALUE = 'ce'\n"}
                    ],
                }
            ],
        }
        self.repository.write("pmorg/build/ce-source-overlay.json", json.dumps(overlay))
        self.repository.write("backend/onyx/community.py", community_base)
        self.repository.write("backend/pmorg/contracts.py", "WIRE = '1.0'\n")
        self.repository.write(
            "backend/requirements/default.txt", "demo==1 --hash=sha256:00\n"
        )
        self.repository.write("backend/ee/secret.py", "SECRET_ENTERPRISE_VALUE = 42\n")
        self.repository.write(
            "web/src/app/page.tsx", "export default function Page() { return null; }\n"
        )
        self.repository.write(
            "web/src/app/ee/secret.tsx", "export const secret = 42;\n"
        )
        self.repository.write("pmorg/README.md", "PMORG synthetic fixture\n")
        self.repository.git("add", ".")
        self.repository.git("commit", "--quiet", "-m", "synthetic CE fixture")
        self.spec = _read_json_object(self.root / "pmorg/build/ce-artifact-spec.json")
        self.overlay = _read_json_object(
            self.root / "pmorg/build/ce-source-overlay.json"
        )

    def test_independent_rebuilds_are_byte_identical(self) -> None:
        first = build_artifact(
            self.root,
            self.root / "first.tar",
            spec_path=self.root / "pmorg/build/ce-artifact-spec.json",
        )
        second = build_artifact(
            self.root,
            self.root / "second.tar",
            spec_path=self.root / "pmorg/build/ce-artifact-spec.json",
        )

        self.assertEqual(first.artifact_sha256, second.artifact_sha256)
        self.assertEqual(
            (self.root / "first.tar").read_bytes(),
            (self.root / "second.tar").read_bytes(),
        )
        with tarfile.open(self.root / "first.tar", mode="r") as archive:
            names = archive.getnames()
            manifest_file = archive.extractfile("PMORG-MANIFEST.json")
            self.assertIsNotNone(manifest_file)
            assert manifest_file is not None
            manifest = json.load(manifest_file)
            community_file = archive.extractfile("backend/onyx/community.py")
            self.assertIsNotNone(community_file)
            assert community_file is not None
            community = community_file.read()
        self.assertEqual(names[0], "PMORG-MANIFEST.json")
        self.assertNotIn("backend/ee/secret.py", names)
        self.assertNotIn("web/src/app/ee/secret.tsx", names)
        self.assertEqual(community, b"VALUE = 'ce'\n")
        self.assertEqual(
            [entry["path"] for entry in manifest["files"]],
            sorted(entry["path"] for entry in manifest["files"]),
        )

    def test_planted_enterprise_path_fails_closed(self) -> None:
        self.repository.write("pmorg/ee/planted.py", "VALUE = 1\n")

        violations = scan_pmorg_worktree(self.root, self.spec)

        self.assertIn("PMORG_EE_PATH", {item.rule for item in violations})

    def test_copied_enterprise_source_in_pmorg_root_fails_closed(self) -> None:
        self.repository.write(
            "pmorg/copied.py",
            (self.root / "backend/ee/secret.py").read_bytes(),
        )

        violations = scan_pmorg_worktree(self.root, self.spec)

        self.assertIn("PMORG_EE_COPY", {item.rule for item in violations})

    def test_enterprise_import_in_pmorg_root_fails_closed(self) -> None:
        self.repository.write("backend/pmorg/bad.py", "from ee.onyx import secret\n")

        violations = scan_pmorg_worktree(self.root, self.spec)

        self.assertIn("PMORG_EE_IMPORT", {item.rule for item in violations})

    def test_egress_inventory_matches_offline_implementation(self) -> None:
        self.assertEqual(
            verify_egress(self.root, self.root / "pmorg/build/ce-build-egress.json"),
            (),
        )
        inventory = _read_json_object(self.root / "pmorg/build/ce-build-egress.json")
        inventory["destinations"] = ["https://undeclared.example.invalid"]
        self.repository.write("pmorg/build/ce-build-egress.json", json.dumps(inventory))

        violations = verify_egress(
            self.root,
            self.root / "pmorg/build/ce-build-egress.json",
        )

        self.assertIn("EGRESS_NETWORK", {item.rule for item in violations})

    def test_named_revision_ignores_worktree_spec_and_overlay_drift(self) -> None:
        first = build_artifact(
            self.root,
            self.root / "before-drift.tar",
            spec_path=self.root / "pmorg/build/ce-artifact-spec.json",
        )
        self.repository.write("pmorg/build/ce-artifact-spec.json", "{}\n")
        self.repository.write("pmorg/build/ce-source-overlay.json", "{}\n")

        second = build_artifact(
            self.root,
            self.root / "after-drift.tar",
            spec_path=self.root / "pmorg/build/ce-artifact-spec.json",
        )

        self.assertEqual(first.artifact_sha256, second.artifact_sha256)

    def test_overlay_digest_drift_fails_closed(self) -> None:
        commit = resolve_commit(self.root, "HEAD")
        entries = selected_entries(self.root, commit, self.spec)
        overlay = json.loads(json.dumps(self.overlay))
        overlay["entries"][0]["base_sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "base digest drifted"):
            apply_overlay(entries, overlay)

    def test_current_mixed_source_is_clean_after_overlay(self) -> None:
        spec = _read_json_object(SPEC_PATH)
        overlay = _read_json_object(OVERLAY_PATH)
        commit = resolve_commit(REPOSITORY_ROOT, "HEAD")
        entries = apply_overlay(
            selected_entries(REPOSITORY_ROOT, commit, spec), overlay
        )

        violations = scan_entries_for_ee(entries, REPOSITORY_ROOT, commit, spec)

        self.assertEqual(violations, ())


if __name__ == "__main__":
    unittest.main()
