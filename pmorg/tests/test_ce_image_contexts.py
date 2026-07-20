from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from pmorg.build.artifact import _canonical_json
from pmorg.build.artifact import _ee_literal_dispatches
from pmorg.build.artifact import _tar_info
from pmorg.build.artifact import MANIFEST_NAME
from pmorg.build.image_context import build_contexts
from pmorg.build.image_context import CONTEXT_MANIFEST_NAME


class TestCeImageContexts(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pmorg-context-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source.tar"
        self.spec = self.root / "contexts.json"
        files = {
            "backend/app.py": b"VALUE = 'backend'\n",
            "backend/requirements/default.txt": b"demo==1\n",
            "web/app.js": b"export const value = 'web';\n",
            "pmorg/README.md": b"not part of either context\n",
        }
        manifest = {
            "schema_version": "pmorg.ce-source-artifact/v1",
            "source_commit": "1" * 40,
            "files": [
                {
                    "mode": "100644",
                    "path": path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
                for path, data in sorted(files.items())
            ],
        }
        manifest_data = _canonical_json(manifest)
        with tarfile.open(self.source, mode="w", format=tarfile.GNU_FORMAT) as archive:
            archive.addfile(
                _tar_info(MANIFEST_NAME, len(manifest_data), 0o644, 0),
                io.BytesIO(manifest_data),
            )
            for path, data in sorted(files.items()):
                archive.addfile(_tar_info(path, len(data), 0o644, 0), io.BytesIO(data))
        self.spec.write_text(
            json.dumps(
                {
                    "schema_version": "pmorg.ce-image-contexts/v1",
                    "source_artifact_schema": "pmorg.ce-source-artifact/v1",
                    "source_date_epoch": 0,
                    "contexts": [
                        {
                            "name": "backend",
                            "source_prefix": "backend/",
                            "required_paths": ["app.py"],
                        },
                        {
                            "name": "web",
                            "source_prefix": "web/",
                            "required_paths": ["app.js"],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

    def test_independent_contexts_are_byte_identical_and_rerooted(self) -> None:
        first = build_contexts(self.source, self.root / "first", spec_path=self.spec)
        second = build_contexts(self.source, self.root / "second", spec_path=self.spec)

        self.assertEqual(
            [(item.name, item.sha256) for item in first],
            [(item.name, item.sha256) for item in second],
        )
        for left, right in zip(first, second, strict=True):
            self.assertEqual(left.path.read_bytes(), right.path.read_bytes())
        with tarfile.open(first[0].path, mode="r:") as archive:
            self.assertEqual(
                archive.getnames(),
                [CONTEXT_MANIFEST_NAME, "app.py", "requirements/default.txt"],
            )

    def test_source_artifact_digest_tamper_fails_closed(self) -> None:
        data = bytearray(self.source.read_bytes())
        data[2048] ^= 1
        self.source.write_bytes(data)

        with self.assertRaisesRegex(ValueError, "digest drifted"):
            build_contexts(self.source, self.root / "tampered", spec_path=self.spec)

    def test_missing_required_context_path_fails_closed(self) -> None:
        spec = json.loads(self.spec.read_text(encoding="utf-8"))
        spec["contexts"][0]["required_paths"].append("missing.py")
        spec["contexts"][0]["required_paths"].sort()
        self.spec.write_text(json.dumps(spec), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "missing required paths"):
            build_contexts(self.source, self.root / "missing", spec_path=self.spec)

    def test_enterprise_literal_requires_fallback_or_noop_dispatch(self) -> None:
        allowed = (
            b"fetch_versioned_implementation_with_fallback('ee.onyx.x', 'x', None)\n"
        )
        denied = b"fetch_versioned_implementation('ee.onyx.x', 'x')\n"

        self.assertEqual(_ee_literal_dispatches("allowed.py", allowed), ())
        self.assertIn(
            "unsafe dispatcher",
            _ee_literal_dispatches("denied.py", denied)[0],
        )


if __name__ == "__main__":
    unittest.main()
