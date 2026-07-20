from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pmorg.boundaries import assert_domain_import_purity
from pmorg.boundaries import DomainImportBoundaryError
from pmorg.boundaries import find_domain_import_violations
from pmorg.contracts import require_supported_wire_surface
from pmorg.contracts import SUPPORTED_WIRE_SURFACES
from pmorg.contracts import UnsupportedWireSurfaceError
from pmorg.contracts import WIRE_SURFACE

PMORG_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_ROOT = PMORG_PACKAGE_ROOT / "domain"


class TestDomainImportBoundary(unittest.TestCase):
    def test_current_domain_is_infrastructure_independent(self) -> None:
        self.assertEqual(find_domain_import_violations(DOMAIN_ROOT), ())

    def test_guard_rejects_infrastructure_and_outer_layer_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            domain_root = Path(temporary_directory) / "backend" / "pmorg" / "domain"
            domain_root.mkdir(parents=True)
            (domain_root / "invalid.py").write_text(
                "import onyx\n"
                "from fastapi import APIRouter\n"
                "from pmorg.integrations import odoo\n"
                "from .. import application\n"
                "import boto3\n",
                encoding="utf-8",
            )

            violations = find_domain_import_violations(domain_root)

        self.assertEqual(
            {violation.imported_module for violation in violations},
            {
                "boto3",
                "fastapi",
                "onyx",
                "pmorg.application",
                "pmorg.integrations",
            },
        )

    def test_guard_allows_standard_library_and_domain_relative_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            domain_root = Path(temporary_directory) / "backend" / "pmorg" / "domain"
            domain_root.mkdir(parents=True)
            (domain_root / "valid.py").write_text(
                "import uuid\nfrom . import values\nfrom pmorg.domain import model\n",
                encoding="utf-8",
            )

            violations = find_domain_import_violations(domain_root)

        self.assertEqual(violations, ())

    def test_assertion_reports_source_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            domain_root = Path(temporary_directory) / "backend" / "pmorg" / "domain"
            domain_root.mkdir(parents=True)
            (domain_root / "invalid.py").write_text(
                "from sqlalchemy import select\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(
                DomainImportBoundaryError,
                r"pmorg/domain/invalid\.py:1: forbidden import sqlalchemy",
            ):
                assert_domain_import_purity(domain_root)


class TestWireSurfaceBoundary(unittest.TestCase):
    def test_only_v3_contract_surface_is_exposed(self) -> None:
        self.assertEqual(WIRE_SURFACE, "pmorg-contracts/1.0")
        self.assertEqual(SUPPORTED_WIRE_SURFACES, {WIRE_SURFACE})
        self.assertEqual(require_supported_wire_surface(WIRE_SURFACE), WIRE_SURFACE)

    def test_v2_and_unknown_surfaces_fail_closed(self) -> None:
        for wire_surface in (
            "orchestrator-contract/1.1",
            "pmorg-memory/1.0",
            "pmorg-contracts/2.0",
            "",
        ):
            with self.subTest(wire_surface=wire_surface):
                with self.assertRaises(UnsupportedWireSurfaceError):
                    require_supported_wire_surface(wire_surface)


if __name__ == "__main__":
    unittest.main()
