from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import unittest
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIRECTORY = REPOSITORY_ROOT / "deployment" / "docker_compose"
COMPOSE_FILES = (
    COMPOSE_DIRECTORY / "docker-compose.yml",
    COMPOSE_DIRECTORY / "docker-compose.pmorg-gate-a.yml",
)
DISABLED_PROFILE = "gate-a-disabled"
BACKEND_IMAGE = f"pmorg/backend-ce@sha256:{'1' * 64}"
WEB_IMAGE = f"pmorg/web-ce@sha256:{'2' * 64}"
POSTGRES_IMAGE = (
    "docker.io/library/postgres:15.18-alpine3.23@sha256:"
    "870f35a8c9eff7ba79a599794120d326df4cecbc6a1bfc0050d58805e37abfaf"
)
DIGEST_REFERENCE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")


def render_compose(*, include_disabled: bool) -> dict[str, Any]:
    command = ["docker", "compose"]
    if include_disabled:
        command.extend(("--profile", DISABLED_PROFILE))
    for compose_file in COMPOSE_FILES:
        command.extend(("-f", str(compose_file)))
    command.extend(("config", "--format", "json"))

    environment = os.environ.copy()
    environment.pop("COMPOSE_PROFILES", None)
    environment.update(
        {
            "HOST_PORT": "3000",
            "PMORG_BACKEND_IMAGE": BACKEND_IMAGE,
            "PMORG_GATE_A_POSTGRES_PASSWORD": "structural-test-only",
            "PMORG_GATE_A_USER_AUTH_SECRET": "0" * 64,
            "PMORG_WEB_IMAGE": WEB_IMAGE,
        }
    )
    completed = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    rendered = json.loads(completed.stdout)
    if not isinstance(rendered, dict):
        raise TypeError("docker compose config did not render a JSON object")
    return rendered


class PmorgGateAComposeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.active = render_compose(include_disabled=False)
        cls.complete = render_compose(include_disabled=True)

    def test_only_postgres_api_and_web_are_active(self) -> None:
        services = self.active["services"]
        self.assertIsInstance(services, dict)
        self.assertEqual(
            set(services),
            {"relational_db", "api_server", "web_server"},
        )

    def test_runtime_network_and_host_ingress_are_constrained(self) -> None:
        networks = self.active["networks"]
        self.assertIsInstance(networks, dict)
        self.assertIs(networks["default"]["internal"], True)

        web = self.active["services"]["web_server"]
        ports = web["ports"]
        self.assertEqual(len(ports), 1)
        self.assertEqual(
            ports[0],
            {
                "mode": "ingress",
                "host_ip": "127.0.0.1",
                "target": 3000,
                "published": "3000",
                "protocol": "tcp",
            },
        )
        self.assertEqual(web["environment"]["INTERNAL_URL"], "http://api_server:8080")
        self.assertEqual(web["environment"]["OVERRIDE_API_PRODUCTION"], "true")

    def test_qualified_artifact_and_infrastructure_digests_are_required(self) -> None:
        services = self.active["services"]
        api_image = services["api_server"]["image"]
        web_image = services["web_server"]["image"]
        self.assertRegex(api_image, DIGEST_REFERENCE)
        self.assertRegex(web_image, DIGEST_REFERENCE)
        self.assertEqual(api_image, BACKEND_IMAGE)
        self.assertEqual(web_image, WEB_IMAGE)
        self.assertEqual(services["relational_db"]["image"], POSTGRES_IMAGE)
        self.assertEqual(services["relational_db"]["platform"], "linux/amd64")
        self.assertEqual(services["api_server"]["pull_policy"], "never")
        self.assertEqual(services["web_server"]["pull_policy"], "never")

        for service in self.complete["services"].values():
            self.assertNotIn("build", service)

    def test_dangerous_base_compose_inheritance_is_removed(self) -> None:
        rendered_text = json.dumps(self.complete, sort_keys=True)
        self.assertNotIn("host-gateway", rendered_text)
        self.assertNotIn("docker.sock", rendered_text)
        self.assertNotIn(":latest", rendered_text)

        for service in self.complete["services"].values():
            self.assertFalse(service.get("extra_hosts"))
            self.assertNotIn("env_file", service)

        api = self.active["services"]["api_server"]
        self.assertFalse(api.get("volumes"))
        self.assertEqual(api["user"], "1001:1001")
        self.assertEqual(api["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", api["security_opt"])

    def test_disabled_endpoints_are_explicitly_cleared(self) -> None:
        environment = self.active["services"]["api_server"]["environment"]
        expected = {
            "AUTO_LLM_CONFIG_URL": "",
            "CODE_INTERPRETER_BASE_URL": "",
            "DISABLE_MODEL_SERVER": "true",
            "DISABLE_VECTOR_DB": "true",
            "INDEXING_MODEL_SERVER_HOST": "disabled",
            "MODEL_SERVER_HOST": "disabled",
            "OPENSEARCH_ADMIN_PASSWORD": "",
            "OPENSEARCH_HOST": "disabled",
            "REDIS_HOST": "disabled",
            "S3_AWS_ACCESS_KEY_ID": "",
            "S3_AWS_SECRET_ACCESS_KEY": "",
            "S3_ENDPOINT_URL": "",
        }
        self.assertEqual({key: environment[key] for key in expected}, expected)
        self.assertEqual(environment["POSTGRES_HOST"], "relational_db")
        self.assertEqual(environment["FILE_STORE_BACKEND"], "postgres")
        self.assertEqual(environment["CACHE_BACKEND"], "postgres")
        self.assertEqual(environment["AUTH_BACKEND"], "postgres")

    def test_excluded_services_are_profiled_and_fail_closed(self) -> None:
        disabled_services = {
            "background",
            "cache",
            "code-interpreter",
            "indexing_model_server",
            "inference_model_server",
            "minio",
            "nginx",
            "opensearch",
        }
        services = self.complete["services"]
        for service_name in disabled_services:
            self.assertEqual(services[service_name]["profiles"], [DISABLED_PROFILE])

        background = services["background"]
        self.assertEqual(background["image"], BACKEND_IMAGE)
        self.assertEqual(background["pull_policy"], "never")
        self.assertEqual(background["restart"], "no")
        self.assertEqual(background["user"], "1001:1001")
        self.assertFalse(background.get("volumes"))
        self.assertIn("outside Gate A", background["command"][-1])

        scoped_out = disabled_services - {"background"}
        for service_name in scoped_out:
            service = services[service_name]
            self.assertTrue(service["image"].startswith("pmorg/scoped-out-"))
            self.assertEqual(service["pull_policy"], "never")
            self.assertEqual(service["restart"], "no")
            self.assertEqual(service["user"], "65534:65534")
            self.assertEqual(service["network_mode"], "none")
            self.assertIs(service["read_only"], True)
            self.assertFalse(service.get("ports"))
            self.assertFalse(service.get("volumes"))
            self.assertIn("outside Gate A", service["entrypoint"][-1])

    def test_ce_flags_and_runtime_license_smoke_mount_are_fail_closed(self) -> None:
        for service_name in ("api_server", "web_server"):
            environment = self.active["services"][service_name]["environment"]
            self.assertEqual(
                environment["ENABLE_PAID_ENTERPRISE_EDITION_FEATURES"], "false"
            )
            self.assertEqual(environment["LICENSE_ENFORCEMENT_ENABLED"], "false")
            targets = {
                item["target"]
                for item in self.active["services"][service_name]["configs"]
            }
            self.assertIn("/PMORG-Platform-LICENSE", targets)

        notice = Path(self.active["configs"]["pmorg_ce_license"]["file"])
        self.assertEqual(notice.resolve(), (REPOSITORY_ROOT / "LICENSE").resolve())


if __name__ == "__main__":
    unittest.main()
