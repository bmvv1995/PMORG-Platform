"""Shared, deterministic fixtures for CE boundary unit tests."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT_DIRECTORY = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from verify_ce_boundary import EVIDENCE_SCHEMA_VERSION  # noqa: E402
from verify_ce_boundary import DockerBuild  # noqa: E402
from verify_ce_boundary import GateConfig  # noqa: E402


class CEBoundaryTestCase(unittest.TestCase):
    SOURCE_REVISION = "c" * 40
    ONYX_REVISION = "1" * 40
    SPECIFICATION_REVISION = "2" * 40

    def setUp(self) -> None:
        self._head_baselines: dict[Path, bytes] = {}
        self._dirty_roots: set[Path] = set()
        self._uv_version = "uv 0.11.25\n"
        self._uv_export_overrides: dict[Path, bytes] = {}
        self._subprocess_commands: list[tuple[str, ...]] = []
        self._subprocess_patcher = patch(
            "verify_ce_boundary.subprocess.run",
            side_effect=self._mock_subprocess_run,
        )
        self._subprocess_patcher.start()
        self.addCleanup(self._subprocess_patcher.stop)

    def _mock_subprocess_run(
        self,
        command: list[str],
        *,
        cwd: Path,
        check: bool,
        stdout: int,
        stderr: int,
    ) -> subprocess.CompletedProcess[bytes]:
        del check, stdout, stderr
        root = Path(cwd).resolve()
        normalized = tuple(command)
        self._subprocess_commands.append(normalized)
        if normalized == ("git", "rev-parse", "--verify", "HEAD"):
            output = f"{self.SOURCE_REVISION}\n".encode()
        elif normalized == (
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ):
            output = b"?? uncommitted-artifact\n" if root in self._dirty_roots else b""
        elif normalized == (
            "git",
            "show",
            "HEAD:pmorg/baseline-manifest.json",
        ):
            output = self._head_baselines[root]
        elif normalized == ("uv", "--version"):
            output = self._uv_version.encode()
        elif normalized[:2] == ("uv", "export"):
            output_index = normalized.index("--output-file") + 1
            generated_path = Path(normalized[output_index])
            payload = self._uv_export_overrides.get(
                root,
                (root / "backend/requirements/default.txt").read_bytes(),
            )
            generated_path.write_bytes(payload)
            output = b""
        else:
            raise AssertionError(f"unexpected subprocess command: {normalized!r}")
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")

    def _write(self, root: Path, relative_path: str, content: str) -> Path:
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _backend_build(self, root: Path) -> DockerBuild:
        dockerfile = root / "backend" / "Dockerfile.pmorg-ce"
        return DockerBuild(
            dockerfile=dockerfile,
            context=root / "backend",
            dockerignore=Path(str(dockerfile) + ".dockerignore"),
        )

    def _web_build(self, root: Path) -> DockerBuild:
        dockerfile = root / "web" / "Dockerfile.pmorg-ce"
        return DockerBuild(
            dockerfile=dockerfile,
            context=root / "web",
            dockerignore=Path(str(dockerfile) + ".dockerignore"),
        )

    def _config(
        self,
        root: Path,
        *,
        mode: str = "source",
        evidence_manifest: Path | None = None,
    ) -> GateConfig:
        return GateConfig(
            repository_root=root,
            builds=(self._backend_build(root), self._web_build(root)),
            mode=mode,
            evidence_manifest=evidence_manifest,
        )

    def _write_clean_source_fixture(self, root: Path) -> None:
        self._write(
            root,
            "backend/Dockerfile.pmorg-ce",
            """\
FROM python:3.13-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
COPY requirements/default.txt /tmp/requirements.txt
RUN uv pip install --system --no-deps --require-hashes -r /tmp/requirements.txt
COPY onyx /app/onyx
""",
        )
        self._write(
            root,
            "backend/Dockerfile.pmorg-ce.dockerignore",
            """\
ee/
requirements/ee.txt
requirements/combined.txt
""",
        )
        self._write(root, "backend/requirements/default.txt", "safe==1.0\n")
        self._write(root, "backend/requirements/ee.txt", "posthog==3.7.4\n")
        self._write(root, "backend/requirements/combined.txt", "-r ee.txt\n")
        self._write(root, "uv.lock", "version = 1\n")
        baseline = {
            "schema_version": "pmorg.platform.baseline/v1",
            "product": "PMORG-Platform",
            "repository": "https://github.com/example/PMORG-Platform.git",
            "upstream": {
                "release_tag": "v4.3.9",
                "commit": self.ONYX_REVISION,
            },
            "specification": {"commit": self.SPECIFICATION_REVISION},
            "build": {
                "target_platform": "linux/amd64",
                "toolchain": {
                    "uv": {
                        "version": "0.11.25",
                        "image": (
                            "ghcr.io/astral-sh/uv:0.11.25@sha256:"
                            "1e3808aa9023d0980e7c15b1fa7c1ac16ff35925780cf5c459858b2d693f01a9"
                        ),
                    }
                },
            },
        }
        baseline_path = self._write(
            root,
            "pmorg/baseline-manifest.json",
            json.dumps(baseline, indent=2) + "\n",
        )
        self._head_baselines[root.resolve()] = baseline_path.read_bytes()
        self._write(
            root,
            "backend/onyx/main.py",
            'import os\n\nMESSAGE = "from ee.onyx.main import app"\n',
        )
        self._write(
            root,
            "backend/ee/onyx/main.py",
            "from ee.onyx.server import enterprise_application\n",
        )
        self._write(
            root,
            "web/src/app/page.tsx",
            """\
// import forbidden from "@/app/ee/admin";
import safeValue from "@/lib/safe";
export default safeValue;
""",
        )
        self._write(root, "web/src/lib/safe.ts", "export default 1;\n")
        self._write(
            root,
            "web/src/app/ee/admin.tsx",
            'import secret from "@/app/ee/secret";\nexport default secret;\n',
        )
        self._write(root, "web/package.json", '{"scripts":{"build":"next build"}}\n')
        self._write(
            root,
            "web/Dockerfile.pmorg-ce",
            """\
FROM node:24-alpine@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
COPY package.json ./
COPY . .
RUN npm run build
""",
        )
        self._write(
            root,
            "web/Dockerfile.pmorg-ce.dockerignore",
            """\
/src/app/ee/
/src/ee/
""",
        )

    def _tar_bytes(self, entries: dict[str, bytes]) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, data in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mtime = 0
                archive.addfile(member, io.BytesIO(data))
        return output.getvalue()

    def _write_tar(self, path: Path, entries: dict[str, bytes]) -> None:
        path.write_bytes(self._tar_bytes(entries))

    def _write_docker_save(
        self,
        path: Path,
        tag: str,
        layer_entries: list[dict[str, bytes]],
        *,
        component: str,
        compress_layers: bool = False,
        diff_ids: list[str] | None = None,
        config_overrides: dict[str, Any] | None = None,
        runtime_overrides: dict[str, Any] | None = None,
        label_overrides: dict[str, str | None] | None = None,
    ) -> str:
        uncompressed_layers = [
            self._tar_bytes(entries) for entries in layer_entries
        ]
        calculated_diff_ids = [
            self._digest_bytes(data) for data in uncompressed_layers
        ]
        layer_payloads = (
            [gzip.compress(data, mtime=0) for data in uncompressed_layers]
            if compress_layers
            else uncompressed_layers
        )
        labels = {
            "org.opencontainers.image.source": (
                "https://github.com/example/PMORG-Platform"
            ),
            "org.opencontainers.image.revision": self.SOURCE_REVISION,
            "io.pmorg.edition": "community",
            "io.pmorg.component": component,
            "io.pmorg.onyx.version": "v4.3.9",
            "io.pmorg.onyx.upstream.revision": self.ONYX_REVISION,
            "io.pmorg.specification.revision": self.SPECIFICATION_REVISION,
            "io.pmorg.build.target-platform": "linux/amd64",
        }
        for key, value in (label_overrides or {}).items():
            if value is None:
                labels.pop(key, None)
            else:
                labels[key] = value
        runtime_config: dict[str, Any] = {
            "Labels": labels,
            "Entrypoint": (
                ["python", "-m", "pmorg_ce.entrypoint"]
                if component == "backend"
                else ["docker-entrypoint.sh"]
            ),
            "Cmd": (
                ["tail", "-f", "/dev/null"]
                if component == "backend"
                else ["node", "server.js"]
            ),
        }
        runtime_config.update(runtime_overrides or {})
        config = {
            "architecture": "amd64",
            "config": runtime_config,
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": diff_ids or calculated_diff_ids,
            },
        }
        config.update(config_overrides or {})
        config_bytes = json.dumps(
            config, sort_keys=True, separators=(",", ":")
        ).encode()
        image_id = self._digest_bytes(config_bytes)
        config_name = f"{image_id.removeprefix('sha256:')}.json"
        layer_names = [
            f"layer-{index}/layer.tar" for index in range(len(layer_payloads))
        ]
        manifest_bytes = json.dumps(
            [{"Config": config_name, "RepoTags": [tag], "Layers": layer_names}],
            sort_keys=True,
        ).encode()
        with tarfile.open(path, mode="w") as docker_save:
            for name, data in (
                ("manifest.json", manifest_bytes),
                (config_name, config_bytes),
                *zip(layer_names, layer_payloads, strict=True),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mtime = 0
                docker_save.addfile(member, io.BytesIO(data))
        return image_id

    def _digest_bytes(self, data: bytes) -> str:
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    def _digest_file(self, path: Path) -> str:
        return self._digest_bytes(path.read_bytes())

    def _image_entry(
        self,
        root: Path,
        name: str,
        tag: str,
        layer_entries: list[dict[str, bytes]],
        filesystem_entries: dict[str, bytes],
        *,
        diff_ids: list[str] | None = None,
    ) -> dict[str, str]:
        archive = root / f"{name}-image.tar"
        image_id = self._write_docker_save(
            archive,
            tag,
            layer_entries,
            component=name,
            diff_ids=diff_ids,
        )
        filesystem = root / f"{name}-filesystem.tar"
        self._write_tar(filesystem, filesystem_entries)
        return {
            "name": name,
            "tag": tag,
            "image_id": image_id,
            "archive": archive.name,
            "archive_sha256": self._digest_file(archive),
            "filesystem": filesystem.name,
            "filesystem_sha256": self._digest_file(filesystem),
            "filesystem_image_id": image_id,
        }

    def _clean_evidence(self, root: Path) -> dict[str, Any]:
        lockfile = root / "uv.lock"
        requirements = root / "backend" / "requirements" / "default.txt"
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "dependency_export": {
                "status": "untrusted-claim",
                "command": [
                    "uv",
                    "export",
                    "--locked",
                    "--no-emit-project",
                    "--no-default-groups",
                    "--group",
                    "backend",
                    "--no-header",
                    "--output-file",
                    "backend/requirements/default.txt",
                ],
                "lockfile": "uv.lock",
                "lockfile_sha256": self._digest_file(lockfile),
                "requirements": "backend/requirements/default.txt",
                "requirements_sha256": self._digest_file(requirements),
            },
            "images": [
                self._image_entry(
                    root,
                    "backend",
                    "pmorg/backend-ce:gate-a",
                    [{"app/onyx/main.py": b"import os\n"}],
                    {"app/onyx/main.py": b"import os\n"},
                ),
                self._image_entry(
                    root,
                    "web",
                    "pmorg/web-ce:gate-a",
                    [{"app/server.js": b"require('http');\n"}],
                    {"app/server.js": b"require('http');\n"},
                ),
            ],
        }

    def _write_evidence(self, root: Path, evidence: dict[str, Any]) -> Path:
        path = root / "gate-a-evidence.json"
        path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        return path

    def _rules(self, report: Any) -> set[str]:
        return {violation.rule for violation in report.violations}

    def _image(self, evidence: dict[str, Any], name: str) -> dict[str, Any]:
        return next(image for image in evidence["images"] if image["name"] == name)

    def _rewrite_image_archive(
        self,
        root: Path,
        evidence: dict[str, Any],
        name: str,
        *,
        config_overrides: dict[str, Any] | None = None,
        runtime_overrides: dict[str, Any] | None = None,
        label_overrides: dict[str, str | None] | None = None,
    ) -> None:
        image = self._image(evidence, name)
        archive = root / image["archive"]
        source_path = "app/onyx/main.py" if name == "backend" else "app/server.js"
        image_id = self._write_docker_save(
            archive,
            image["tag"],
            [{source_path: b"import os\n"}],
            component=name,
            config_overrides=config_overrides,
            runtime_overrides=runtime_overrides,
            label_overrides=label_overrides,
        )
        image["image_id"] = image_id
        image["filesystem_image_id"] = image_id
        image["archive_sha256"] = self._digest_file(archive)
