from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CE_DOCKERFILES = (
    REPOSITORY_ROOT / "backend" / "Dockerfile.pmorg-ce",
    REPOSITORY_ROOT / "web" / "Dockerfile.pmorg-ce",
)
COMPOSE_OVERLAY = (
    REPOSITORY_ROOT
    / "deployment"
    / "docker_compose"
    / "docker-compose.pmorg-ce.yml"
)
SETTINGS_API = (
    REPOSITORY_ROOT
    / "backend"
    / "onyx"
    / "server"
    / "settings"
    / "api.py"
)


class PmorgCeRuntimeSourcePolicyTests(unittest.TestCase):
    def test_ce_dockerfiles_require_and_validate_full_lowercase_revision(self) -> None:
        for dockerfile in CE_DOCKERFILES:
            with self.subTest(dockerfile=dockerfile.relative_to(REPOSITORY_ROOT)):
                source = dockerfile.read_text(encoding="utf-8")

                self.assertNotRegex(source, r"ARG PMORG_FORK_REVISION\s*=")
                self.assertNotIn("uncommitted", source)
                self.assertGreaterEqual(
                    len(re.findall(r"^ARG PMORG_FORK_REVISION$", source, re.MULTILINE)),
                    2,
                )
                self.assertIn('${#PMORG_FORK_REVISION}" -ne 40', source)
                self.assertIn("*[!0-9a-f]*", source)
                self.assertIn(
                    'org.opencontainers.image.revision="${PMORG_FORK_REVISION}"',
                    source,
                )

    def test_backend_image_fixes_networked_configuration_defaults(self) -> None:
        source = CE_DOCKERFILES[0].read_text(encoding="utf-8")

        self.assertIn('io.pmorg.component="backend"', source)
        self.assertIn('DISABLE_TELEMETRY="true"', source)
        self.assertIn('AUTO_LLM_CONFIG_URL=""', source)

    def test_community_settings_seam_has_no_enterprise_tier_lookup(self) -> None:
        source = SETTINGS_API.read_text(encoding="utf-8")

        self.assertNotIn("global_version", source)
        self.assertNotIn("from ee.", source)
        self.assertIn("current_tier = Tier.COMMUNITY", source)

    def test_web_image_identifies_component_and_preserves_node_entrypoint(self) -> None:
        source = CE_DOCKERFILES[1].read_text(encoding="utf-8")

        self.assertIn('io.pmorg.component="web"', source)
        entrypoint = 'ENTRYPOINT ["docker-entrypoint.sh"]'
        command = 'CMD ["node", "server.js"]'
        self.assertIn(entrypoint, source)
        self.assertLess(source.index(entrypoint), source.index(command))

    def test_compose_requires_revision_and_fixes_backend_runtime_values(self) -> None:
        source = COMPOSE_OVERLAY.read_text(encoding="utf-8")

        self.assertNotIn("uncommitted", source)
        self.assertEqual(
            source.count("PMORG_FORK_REVISION: \"${PMORG_FORK_REVISION:?"),
            3,
        )
        self.assertEqual(source.count('DISABLE_TELEMETRY: "true"'), 2)
        self.assertEqual(source.count('AUTO_LLM_CONFIG_URL: ""'), 2)


if __name__ == "__main__":
    unittest.main()
