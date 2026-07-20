from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from verify_fork import changed_paths_from_revision  # noqa: E402
from verify_fork import COMMON_QUALIFICATION_REF_KEYS  # noqa: E402
from verify_fork import find_path_owners  # noqa: E402
from verify_fork import load_manifest  # noqa: E402
from verify_fork import load_ownership_roots  # noqa: E402
from verify_fork import load_patch_ledger  # noqa: E402
from verify_fork import load_seam_allowlist  # noqa: E402
from verify_fork import PatchEntry  # noqa: E402
from verify_fork import protector_test_executes_exactly_once  # noqa: E402
from verify_fork import validate_build_qualification_state  # noqa: E402
from verify_fork import validate_local_upstream  # noqa: E402
from verify_fork import validate_ownership_roots  # noqa: E402
from verify_fork import validate_patch_entries  # noqa: E402
from verify_fork import validate_patch_ledger_contract  # noqa: E402
from verify_fork import validate_round_3_contract  # noqa: E402
from verify_fork import validate_seam_allowlist  # noqa: E402
from verify_fork import validate_specification_references  # noqa: E402
from verify_fork import validate_surface_mode  # noqa: E402
from verify_fork import validate_thin_fork_diff  # noqa: E402
from verify_fork import validate_upstream_patch_record  # noqa: E402


class ForkLedgerTest(unittest.TestCase):
    def test_rename_is_enumerated_as_deletion_and_addition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=repository_root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@pmorg.invalid"],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "PMORG Test"],
                cwd=repository_root,
                check=True,
            )
            old_path = repository_root / "backend/onyx/old.py"
            new_path = repository_root / "backend/onyx/new.py"
            old_path.parent.mkdir(parents=True)
            old_path.write_text("VALUE = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repository_root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "upstream"],
                cwd=repository_root,
                check=True,
            )
            upstream_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "mv", str(old_path), str(new_path)],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-q", "-m", "rename"],
                cwd=repository_root,
                check=True,
            )

            self.assertEqual(
                changed_paths_from_revision(repository_root, upstream_commit),
                ["backend/onyx/new.py", "backend/onyx/old.py"],
            )

    def test_dynamic_route_brackets_are_literal(self) -> None:
        route = "web/src/app/admin/bots/[bot-id]/channels/[id]/page.tsx"
        entries: list[PatchEntry] = [
            {
                "id": "PL-TEST",
                "classification": "integration",
                "paths": [route],
            }
        ]

        owners = find_path_owners(
            [route, "web/src/app/admin/bots/b/channels/i/page.tsx"], entries
        )

        self.assertEqual(owners[route], ["PL-TEST"])
        self.assertEqual(owners["web/src/app/admin/bots/b/channels/i/page.tsx"], [])

    def test_overlapping_entries_are_reported_as_multiple_owners(self) -> None:
        path = "pmorg/scripts/verify_fork.py"
        entries: list[PatchEntry] = [
            {
                "id": "PL-BROAD",
                "classification": "PMORG-owned",
                "paths": ["pmorg/**"],
            },
            {
                "id": "PL-NARROW",
                "classification": "PMORG-owned",
                "paths": [path],
            },
        ]

        self.assertEqual(
            find_path_owners([path], entries)[path],
            ["PL-BROAD", "PL-NARROW"],
        )

    def test_current_foundation_paths_have_one_owner(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        ledger = load_patch_ledger(repository_root)
        paths = [
            "PMORG.md",
            ".codex/agents/pmorg-mapper.toml",
            "plans/pmorg-v3-foundation.md",
            "pmorg/CE-BOUNDARY.md",
            "pmorg/scripts/verify_fork.py",
            "pmorg/tests/test_verify_fork.py",
        ]

        self.assertEqual(
            find_path_owners(paths, ledger["entries"]),
            {
                paths[0]: ["PL-000"],
                paths[1]: ["PL-001"],
                paths[2]: ["PL-002"],
                paths[3]: ["PL-000"],
                paths[4]: ["PL-000"],
                paths[5]: ["PL-000"],
            },
        )

    def test_specification_pin_is_cross_recorded(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = load_manifest(repository_root)
        ledger = load_patch_ledger(repository_root)

        self.assertEqual(manifest["specification"]["baseline"], "RB-1/C2")
        self.assertEqual(
            manifest["specification"]["commit"],
            ledger["specification_commit"],
        )
        self.assertEqual(
            validate_specification_references(
                repository_root, manifest["specification"]["commit"]
            ),
            [],
        )

    def test_current_surface_mode_policy_is_valid(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = load_manifest(repository_root)

        self.assertEqual(validate_surface_mode(manifest), [])

    def test_surface_and_mode_must_be_declared_together(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = copy.deepcopy(load_manifest(repository_root))
        manifest["build"]["onyx_surface"] = "ee"

        self.assertIn(
            "onyx_surface and usage_mode must be declared together",
            validate_surface_mode(manifest),
        )

    def test_legacy_licensed_ee_value_is_rejected(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = copy.deepcopy(load_manifest(repository_root))
        manifest["build"]["onyx_surface"] = "licensed-ee"
        manifest["build"]["usage_mode"] = "production"

        errors = validate_surface_mode(manifest)

        self.assertIn("invalid onyx_surface: licensed-ee", errors)
        self.assertIn("legacy delivery-profile terminology is forbidden", errors)

    def test_unknown_usage_mode_is_rejected(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        manifest = copy.deepcopy(load_manifest(repository_root))
        manifest["build"]["onyx_surface"] = "ce"
        manifest["build"]["usage_mode"] = "client"

        self.assertIn(
            "invalid usage_mode: client",
            validate_surface_mode(manifest),
        )

    def test_patch_entry_requires_traceability_fields(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        ledger = load_patch_ledger(repository_root)
        broken_entry = copy.deepcopy(ledger["entries"][0])
        broken_entry.pop("requirements")

        self.assertIn(
            "PL-000 has no non-empty requirements list",
            validate_patch_entries([broken_entry]),
        )

    def test_patch_entry_rejects_empty_reason_and_verification(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        ledger = load_patch_ledger(repository_root)
        broken_entry = copy.deepcopy(ledger["entries"][0])
        broken_entry["reason"] = " "
        broken_entry["verification"] = []

        errors = validate_patch_entries([broken_entry])

        self.assertIn("PL-000 has no non-empty reason", errors)
        self.assertIn("PL-000 has no non-empty verification list", errors)

    def test_upstream_check_allows_clean_origin_only_clone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            subprocess.run(
                ["git", "init", "-q"],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "test@pmorg.invalid"],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "PMORG Test"],
                cwd=repository_root,
                check=True,
            )
            (repository_root / "fixture.txt").write_text("fixture\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "fixture.txt"],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-q", "-m", "fixture"],
                cwd=repository_root,
                check=True,
            )
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            upstream = {
                "repository": "https://github.com/onyx-dot-app/onyx.git",
                "release_tag": "v4.3.9",
                "commit": commit,
                "checkout_remote": "upstream",
            }

            self.assertEqual(validate_local_upstream(repository_root, upstream), [])

    def test_upstream_check_reports_missing_commit_without_traceback(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        upstream = {
            "repository": "https://github.com/onyx-dot-app/onyx.git",
            "release_tag": "v4.3.9",
            "commit": "0" * 40,
            "checkout_remote": "upstream",
        }

        self.assertIn(
            "pinned upstream commit is absent from local history",
            validate_local_upstream(repository_root, upstream),
        )


class RoundThreeBootstrapTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repository_root = Path(__file__).resolve().parents[2]

    def test_current_round_three_contract_is_complete(self) -> None:
        manifest = load_manifest(self.repository_root)

        self.assertEqual(validate_round_3_contract(manifest), [])
        self.assertEqual(validate_build_qualification_state(manifest), [])

    def test_pmorg_commit_remains_normative_over_manifest_snapshot(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["round_3_contract"]["authority"] = "manifest_is_normative"

        self.assertIn(
            "round-3 manifest contract must declare the PMORG commit normative",
            validate_round_3_contract(manifest),
        )

    def test_accepted_pmorg_specification_pin_is_literal_not_circular(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        alternate_commit = "0" * 40
        manifest["specification"]["commit"] = alternate_commit
        manifest["round_3_contract"]["source_specification_commit"] = alternate_commit

        self.assertIn(
            "baseline is not pinned to the accepted PMORG specification commit",
            validate_round_3_contract(manifest),
        )

    def test_plt_008_and_distribution_contract_cannot_be_removed(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["round_3_contract"]["platform_requirements"] = [
            requirement
            for requirement in manifest["round_3_contract"]["platform_requirements"]
            if requirement != "PLT-008"
        ]
        manifest["round_3_contract"]["distribution_admission"][
            "required_contracts"
        ].remove("distribution-admission-dsse")

        errors = validate_round_3_contract(manifest)

        self.assertIn(
            "round-3 platform requirements must include PLT-001 and PLT-004..008",
            errors,
        )
        self.assertIn(
            "distribution evidence/admission contract set is incomplete",
            errors,
        )

    def test_runtime_scope_policy_map_cannot_be_reduced(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["round_3_contract"]["runtime_scope_policy_classes"].pop()

        self.assertIn(
            "runtime scope policy classes must be deployment_runtime, "
            "registry_publish and artifact_export",
            validate_round_3_contract(manifest),
        )

    def test_bootstrap_status_and_license_boundaries_are_fixed(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["status"] = "production_ready"
        manifest["licensing"]["source_repository_mode"] = "community_only"
        manifest["licensing"]["enterprise_license_paths"].pop()

        self.assertIn(
            "Slice 0 baseline status must remain bootstrap_candidate",
            validate_round_3_contract(manifest),
        )
        surface_errors = validate_surface_mode(manifest)
        self.assertIn("source repository mode must remain mixed_source", surface_errors)
        self.assertIn(
            "Enterprise license path boundary is incomplete or reordered",
            surface_errors,
        )

    def test_allowed_reproducibility_differences_are_exact(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["round_3_contract"]["build_qualification"][
            "allowed_reproducibility_differences"
        ].append("artifact_set_hash")

        self.assertIn(
            "allowed reproducibility difference set is invalid",
            validate_round_3_contract(manifest),
        )

    def test_qualification_role_set_is_exact_and_surface_conditional(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["round_3_contract"]["qualification_bundle_roles"]["common"].remove(
            "capability-evidence-bundle-index"
        )

        self.assertIn(
            "qualification bundle logical-role set is incomplete",
            validate_round_3_contract(manifest),
        )

    def test_offline_evidence_and_trusted_time_flags_are_fail_closed(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["round_3_contract"]["evidence_policy"][
            "content_addressed_bytes_resolve_offline"
        ] = False
        manifest["round_3_contract"]["trusted_time_policy"][
            "future_dated_signed_times_forbidden"
        ] = False

        errors = validate_round_3_contract(manifest)

        self.assertIn(
            "round-3 policy evidence_policy.content_addressed_bytes_resolve_offline must be true",
            errors,
        )
        self.assertIn(
            "round-3 policy trusted_time_policy.future_dated_signed_times_forbidden must be true",
            errors,
        )

    def test_deployment_has_four_pass_and_four_opposite_denials(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        deployment = manifest["round_3_contract"]["deployment_admission"]
        self.assertEqual(len(deployment["pass_matrix"]), 4)
        self.assertEqual(len(deployment["deny_matrix"]), 4)

        deployment["deny_matrix"][2]["target_class"] = "client"

        self.assertIn(
            "deployment admission must declare exactly four opposite-class denials",
            validate_round_3_contract(manifest),
        )

    def test_distribution_has_four_pass_and_four_opposite_denials(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        distribution = manifest["round_3_contract"]["distribution_admission"]
        self.assertEqual(len(distribution["pass_matrix"]), 4)
        self.assertEqual(len(distribution["deny_matrix"]), 4)

        distribution["pass_matrix"][3]["authorization"] = "none"

        self.assertIn(
            "distribution admission must declare exactly four PASS cells",
            validate_round_3_contract(manifest),
        )

    def test_bootstrap_keeps_every_dynamic_reference_null(self) -> None:
        manifest = load_manifest(self.repository_root)
        build = manifest["build"]

        self.assertEqual(build["mode"], "not_yet_qualified")
        self.assertTrue(
            all(value is None for value in build["qualification_refs"].values())
        )
        self.assertTrue(all(value == [] for value in build["operation_refs"].values()))

    def test_claiming_qualified_without_evidence_fails_closed(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["build"]["mode"] = "qualified"
        manifest["build"]["onyx_surface"] = "ce"
        manifest["build"]["usage_mode"] = "development_test"
        manifest["licensing"]["qualification_status"] = "qualified"

        errors = validate_build_qualification_state(manifest)

        self.assertTrue(
            any(
                error.startswith(
                    "qualified build has missing or invalid qualification refs:"
                )
                for error in errors
            )
        )
        self.assertIn(
            "qualified CE build requires only ce_boundary_report_hash",
            errors,
        )

    def test_structurally_complete_hashes_still_cannot_qualify_slice_zero(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        digest = "sha256:" + "a" * 64
        manifest["build"]["mode"] = "qualified"
        manifest["build"]["onyx_surface"] = "ce"
        manifest["build"]["usage_mode"] = "development_test"
        manifest["licensing"]["qualification_status"] = "qualified"
        for key in COMMON_QUALIFICATION_REF_KEYS:
            manifest["build"]["qualification_refs"][key] = digest
        manifest["build"]["qualification_refs"]["ce_boundary_report_hash"] = digest

        self.assertEqual(
            validate_build_qualification_state(manifest),
            [
                "Slice 0 verifier cannot admit a qualified build without "
                "canonical offline evidence and DSSE verification"
            ],
        )

    def test_wrong_surface_report_and_partial_operation_refs_are_rejected(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        digest = "sha256:" + "b" * 64
        manifest["build"]["qualification_refs"]["ee_inventory_report_hash"] = digest
        manifest["build"]["operation_refs"]["deployment_admission_envelope_hashes"] = [
            digest
        ]

        errors = validate_build_qualification_state(manifest)

        self.assertTrue(
            any(
                error.startswith("not_yet_qualified build must keep")
                for error in errors
            )
        )
        self.assertTrue(
            any(
                error.startswith("Slice 0 operation ref arrays must remain empty")
                for error in errors
            )
        )


class ThinForkPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repository_root = Path(__file__).resolve().parents[2]
        self.ledger = load_patch_ledger(self.repository_root)
        self.ownership_policy = load_ownership_roots(self.repository_root, self.ledger)
        self.seam_policy = load_seam_allowlist(self.repository_root, self.ledger)
        self.adr_ref = "pmorg/adr/ADR-TEST-seam-authorization.json"
        self.protector_ref = (
            "pmorg/tests/test_seam_protector.py::TestProtector.test_exact_seam"
        )
        self.test_seam_policy = copy.deepcopy(self.seam_policy)
        self.test_seam_policy["seams"] = [
            {
                "seam_id": "SEAM-TEST",
                "path_pattern": "backend/onyx/example.py",
                "authorization_adr_ref": self.adr_ref,
                "authorization_commit": "a" * 40,
                "authorization_base_commit": "a" * 40,
                "authorization_blob_hash": "sha256:" + "b" * 64,
                "allowed_classifications": ["integration"],
                "required_protector_tests": [self.protector_ref],
                "reason": "Bounded test seam.",
            }
        ]
        self.integration_entries = copy.deepcopy(self.ledger["entries"])
        self.integration_entries.append(
            {
                "id": "PL-TEST-INTEGRATION",
                "classification": "integration",
                "paths": ["backend/onyx/example.py"],
                "requirements": ["PLT-004"],
                "reason": "Own the simulated exact integration seam.",
                "verification": [self.protector_ref],
            }
        )
        self.valid_upstream_record = {
            "id": "UP-TEST",
            "path": "backend/onyx/example.py",
            "seam_id": "SEAM-TEST",
            "classification": "integration",
            "base_blob_hash": "sha256:" + "1" * 64,
            "patched_blob_hash": "sha256:" + "2" * 64,
            "base_git_mode": "100644",
            "patched_git_mode": "100644",
            "upstream_source_ref": {
                "repository": "https://github.com/onyx-dot-app/onyx.git",
                "commit": self.ledger["upstream_commit"],
                "path": "backend/onyx/example.py",
                "tree_hash": "sha256:" + "3" * 64,
            },
            "reason": "Wire a bounded PMORG integration seam.",
            "owner": "pmorg-platform",
            "upstream_issue_url": None,
            "upstream_pr_url": None,
            "requirement_refs": ["PLT-004"],
            "capability_refs": [],
            "ownership_class": "upstream_ce_direct_patch",
            "license_class": "mit-expat",
            "onyx_surfaces": ["ce", "ee"],
            "protector_tests": [self.protector_ref],
            "last_revalidated_at": "2026-07-19T00:00:00Z",
            "conflict_notes": "none observed",
            "removal_condition": None,
        }

    def prepare_authorization_repository(
        self,
        repository_root: Path,
        policy: dict[str, object],
        *,
        protector_source: str | None = None,
        write_protector: bool = True,
        delete_and_restore_evidence_on_seam_change: bool = False,
        add_intermediate_commit: bool = False,
        authorization_overrides: dict[str, object] | None = None,
    ) -> str:
        seam = policy["seams"][0]
        protector_path_text, _, _ = self.protector_ref.partition("::")
        protector_path = repository_root / protector_path_text
        protector_source = protector_source or (
            "import unittest\n\n"
            "class TestProtector(unittest.TestCase):\n"
            "    def test_exact_seam(self) -> None:\n"
            "        pass\n"
        )
        if write_protector:
            protector_path.parent.mkdir(parents=True, exist_ok=True)
            protector_path.write_text(protector_source, encoding="utf-8")
            protector_bytes = protector_path.read_bytes()
        else:
            protector_bytes = b"missing-protector"
        governed_path = repository_root / seam["path_pattern"]
        base_bytes = b"BASE\n"
        patched_bytes = b"PATCHED\n"
        governed_path.parent.mkdir(parents=True, exist_ok=True)
        governed_path.write_bytes(base_bytes)

        authorization = {
            "schema_version": "pmorg.platform.seam-authorization/v1",
            "decision_id": "ADR-TEST",
            "status": "accepted",
            "specification_commit": self.ledger["specification_commit"],
            "seam_id": seam["seam_id"],
            "path": seam["path_pattern"],
            "allowed_classifications": seam["allowed_classifications"],
            "required_protector_tests": seam["required_protector_tests"],
            "protector_test_hashes": {
                self.protector_ref: "sha256:"
                + hashlib.sha256(protector_bytes).hexdigest()
            },
            "authorized_at": "2026-07-19T10:00:00Z",
            "rationale": "Authorize the exact simulated seam for verifier tests.",
        }
        if authorization_overrides:
            authorization.update(authorization_overrides)
        authorization_path = repository_root / self.adr_ref
        authorization_path.parent.mkdir(parents=True, exist_ok=True)
        authorization_path.write_text(
            json.dumps(authorization, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        subprocess.run(["git", "init", "-q"], cwd=repository_root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=repository_root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "PMORG Test"],
            cwd=repository_root,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=repository_root, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "authorize seam"],
            cwd=repository_root,
            check=True,
        )
        authorization_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        seam["authorization_commit"] = authorization_commit
        protected_base = authorization_commit
        authorization_bytes = authorization_path.read_bytes()
        if delete_and_restore_evidence_on_seam_change:
            if not write_protector:
                self.fail("delete/restore fixture requires an existing protector")
            authorization_path.unlink()
            protector_path.unlink()
            subprocess.run(["git", "add", "-u"], cwd=repository_root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "remove authorization evidence"],
                cwd=repository_root,
                check=True,
            )
            protected_base = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            authorization_path.write_bytes(authorization_bytes)
            protector_path.write_bytes(protector_bytes)
            subprocess.run(
                ["git", "add", str(authorization_path), str(protector_path)],
                cwd=repository_root,
                check=True,
            )
        if add_intermediate_commit:
            intermediate = repository_root / "intermediate.txt"
            intermediate.write_text("must not precede seam commit\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", str(intermediate)], cwd=repository_root, check=True
            )
            subprocess.run(
                ["git", "commit", "-q", "-m", "intermediate change"],
                cwd=repository_root,
                check=True,
            )
        seam["authorization_base_commit"] = protected_base
        seam["authorization_blob_hash"] = (
            "sha256:" + hashlib.sha256(authorization_bytes).hexdigest()
        )

        policy_path = repository_root / "pmorg/policies/seam-allowlist.json"
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(
            json.dumps(policy, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        record = copy.deepcopy(self.valid_upstream_record)
        record.update(
            {
                "path": seam["path_pattern"],
                "seam_id": seam["seam_id"],
                "base_blob_hash": self._successor_fixture_hash(base_bytes),
                "patched_blob_hash": self._successor_fixture_hash(patched_bytes),
                "protector_tests": seam["required_protector_tests"],
            }
        )
        record["upstream_source_ref"]["path"] = seam["path_pattern"]
        owner = {
            "id": "PL-TEST-INTEGRATION",
            "classification": "integration",
            "paths": [seam["path_pattern"]],
            "requirements": ["PLT-004"],
            "reason": "Own the simulated exact integration seam.",
            "verification": [self.protector_ref],
        }
        ledger_path = repository_root / "pmorg/patch-ledger.json"
        self._write_successor_fixture_json(
            ledger_path,
            {"upstream_patch_records": [record], "entries": [owner]},
        )
        governed_path.write_bytes(patched_bytes)
        marker = repository_root / "seam-change-marker.txt"
        marker.write_text("simulated later seam change\n", encoding="utf-8")
        subprocess.run(
            [
                "git",
                "add",
                str(governed_path),
                str(ledger_path),
                str(marker),
                str(policy_path),
            ],
            cwd=repository_root,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-q", "-m", "apply seam"],
            cwd=repository_root,
            check=True,
        )
        return protected_base

    @staticmethod
    def _write_successor_fixture_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    @staticmethod
    def _commit_successor_fixture(repository_root: Path, message: str) -> str:
        subprocess.run(["git", "add", "."], cwd=repository_root, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", message],
            cwd=repository_root,
            check=True,
        )
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @staticmethod
    def _successor_fixture_hash(value: bytes) -> str:
        return "sha256:" + hashlib.sha256(value).hexdigest()

    def _prepare_successor_lifecycle_repository(
        self,
        repository_root: Path,
        *,
        predecessor_seam_id: str = "SEAM-SUCCESSOR-A",
        successor_authorized: bool = True,
        add_intermediate_commit: bool = False,
        replay_record_and_owner_ids: bool = False,
        double_ownership: bool = False,
        target_hash_mismatch: bool = False,
        canonical_identity_drift: bool = False,
        predecessor_record_id: str = "UP-SUCCESSOR-A",
        successor_owner_classification: str = "integration",
    ) -> dict[str, object]:
        path = "backend/onyx/example.py"
        policy_path = repository_root / "pmorg/policies/seam-allowlist.json"
        ledger_path = repository_root / "pmorg/patch-ledger.json"
        target_path = repository_root / path
        normal_adr_ref = "pmorg/adr/ADR-SUCCESSOR-A.json"
        successor_adr_ref = "pmorg/adr/ADR-SUCCESSOR-B.json"
        normal_test_ref = (
            "pmorg/tests/test_successor_a.py::TestProtector.test_exact_target"
        )
        successor_test_ref = (
            "pmorg/tests/test_successor_b.py::TestProtector.test_exact_target"
        )
        normal_test_path = repository_root / normal_test_ref.partition("::")[0]
        successor_test_path = repository_root / successor_test_ref.partition("::")[0]

        subprocess.run(["git", "init", "-q"], cwd=repository_root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=repository_root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "PMORG Test"],
            cwd=repository_root,
            check=True,
        )

        base_bytes = b"BASE\n"
        a_bytes = b"PATCH-A\n"
        b_bytes = b"PATCH-B\n"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(base_bytes)
        upstream_commit = self._commit_successor_fixture(
            repository_root, "upstream baseline"
        )
        upstream_tree = subprocess.run(
            ["git", "ls-tree", "-r", "-z", upstream_commit],
            cwd=repository_root,
            check=True,
            capture_output=True,
        ).stdout

        normal_test_source = (
            "import unittest\n\n"
            "class TestProtector(unittest.TestCase):\n"
            "    def test_exact_target(self) -> None:\n"
            f"        self.assertEqual((REPOSITORY_ROOT / {path!r}).read_bytes(), "
            f"{a_bytes!r})\n"
        )
        normal_test_path.parent.mkdir(parents=True, exist_ok=True)
        normal_test_path.write_text(normal_test_source, encoding="utf-8")
        normal_authorization = {
            "schema_version": "pmorg.platform.seam-authorization/v1",
            "decision_id": "ADR-SUCCESSOR-A",
            "status": "accepted",
            "specification_commit": self.ledger["specification_commit"],
            "seam_id": "SEAM-SUCCESSOR-A",
            "path": path,
            "allowed_classifications": ["integration"],
            "required_protector_tests": [normal_test_ref],
            "protector_test_hashes": {
                normal_test_ref: self._successor_fixture_hash(
                    normal_test_path.read_bytes()
                )
            },
            "authorized_at": "2026-07-20T00:00:00Z",
            "rationale": "Authorize the first exact fixture seam generation.",
        }
        normal_adr_path = repository_root / normal_adr_ref
        self._write_successor_fixture_json(normal_adr_path, normal_authorization)
        empty_policy = copy.deepcopy(self.seam_policy)
        empty_policy["seams"] = []
        self._write_successor_fixture_json(policy_path, empty_policy)
        self._write_successor_fixture_json(
            ledger_path, {"upstream_patch_records": [], "entries": []}
        )
        normal_authorization_commit = self._commit_successor_fixture(
            repository_root, "authorize normal seam generation"
        )
        normal_authorization_hash = self._successor_fixture_hash(
            normal_adr_path.read_bytes()
        )

        seam_a = {
            "seam_id": "SEAM-SUCCESSOR-A",
            "path_pattern": path,
            "authorization_adr_ref": normal_adr_ref,
            "authorization_commit": normal_authorization_commit,
            "authorization_base_commit": normal_authorization_commit,
            "authorization_blob_hash": normal_authorization_hash,
            "allowed_classifications": ["integration"],
            "required_protector_tests": [normal_test_ref],
            "reason": "Admit the first exact fixture seam generation.",
        }
        record_a = copy.deepcopy(self.valid_upstream_record)
        record_a.update(
            {
                "id": "UP-SUCCESSOR-A",
                "path": path,
                "seam_id": "SEAM-SUCCESSOR-A",
                "base_blob_hash": self._successor_fixture_hash(base_bytes),
                "patched_blob_hash": self._successor_fixture_hash(a_bytes),
                "upstream_source_ref": {
                    "repository": "https://github.com/onyx-dot-app/onyx.git",
                    "commit": upstream_commit,
                    "path": path,
                    "tree_hash": self._successor_fixture_hash(upstream_tree),
                },
                "protector_tests": [normal_test_ref],
            }
        )
        owner_a = {
            "id": "PL-SUCCESSOR-A",
            "classification": "integration",
            "paths": [path],
            "requirements": ["PLT-004"],
            "reason": "Own the first exact fixture seam generation.",
            "verification": [normal_test_ref],
        }
        policy_a = copy.deepcopy(empty_policy)
        policy_a["seams"] = [seam_a]
        target_path.write_bytes(a_bytes)
        self._write_successor_fixture_json(policy_path, policy_a)
        self._write_successor_fixture_json(
            ledger_path,
            {"upstream_patch_records": [record_a], "entries": [owner_a]},
        )
        normal_activation_commit = self._commit_successor_fixture(
            repository_root, "activate normal seam record owner and bytes"
        )

        self.assertEqual(
            validate_seam_allowlist(
                policy_a,
                repository_root,
                self.ownership_policy,
                repository_root,
                normal_authorization_commit,
            ),
            [],
        )
        self.assertEqual(
            validate_thin_fork_diff(
                [path],
                [owner_a],
                [record_a],
                self.ownership_policy,
                policy_a,
                repository_root,
                upstream_commit,
            ),
            [],
        )

        successor_test_source = (
            "import unittest\n\n"
            "class TestProtector(unittest.TestCase):\n"
            "    def test_exact_target(self) -> None:\n"
            f"        self.assertEqual((REPOSITORY_ROOT / {path!r}).read_bytes(), "
            f"{b_bytes!r})\n"
        )
        successor_test_path.parent.mkdir(parents=True, exist_ok=True)
        successor_test_path.write_text(successor_test_source, encoding="utf-8")
        successor_record_id = (
            "UP-SUCCESSOR-A" if replay_record_and_owner_ids else "UP-SUCCESSOR-B"
        )
        successor_owner_id = (
            "PL-SUCCESSOR-A" if replay_record_and_owner_ids else "PL-SUCCESSOR-B"
        )
        successor_authorization = {
            "schema_version": (
                "pmorg.platform.seam-successor-authorization/v1"
                if successor_authorized
                else "pmorg.platform.seam-authorization/v1"
            ),
            "decision_id": "ADR-SUCCESSOR-B",
            "status": "accepted",
            "specification_commit": self.ledger["specification_commit"],
            "seam_id": "SEAM-SUCCESSOR-B",
            "path": path,
            "allowed_classifications": ["integration"],
            "required_protector_tests": [successor_test_ref],
            "protector_test_hashes": {
                successor_test_ref: self._successor_fixture_hash(
                    successor_test_path.read_bytes()
                )
            },
            "authorized_at": "2026-07-20T00:01:00Z",
            "rationale": "Authorize the exact successor fixture generation.",
        }
        if successor_authorized:
            successor_authorization.update(
                {
                    "transition_id": "TRANSITION-SUCCESSOR-A-B",
                    "supersedes": {
                        "seam_id": predecessor_seam_id,
                        "patch_record_id": predecessor_record_id,
                        "ledger_entry_id": "PL-SUCCESSOR-A",
                        "patched_blob_hash": self._successor_fixture_hash(a_bytes),
                        "patched_git_mode": "100644",
                        "authorization_adr_ref": normal_adr_ref,
                        "authorization_blob_hash": normal_authorization_hash,
                    },
                    "successor_patch_record_id": successor_record_id,
                    "successor_ledger_entry_id": successor_owner_id,
                    "target_blob_hash": self._successor_fixture_hash(
                        b"AUTHORIZED-BUT-NOT-ACTIVATED\n"
                        if target_hash_mismatch
                        else b_bytes
                    ),
                    "target_git_mode": "100644",
                }
            )
        successor_adr_path = repository_root / successor_adr_ref
        self._write_successor_fixture_json(successor_adr_path, successor_authorization)
        successor_authorization_commit = self._commit_successor_fixture(
            repository_root, "bootstrap successor authorization and protector"
        )
        successor_authorization_hash = self._successor_fixture_hash(
            successor_adr_path.read_bytes()
        )

        if add_intermediate_commit:
            (repository_root / "intermediate.txt").write_text(
                "separates protected base from activation\n", encoding="utf-8"
            )
            self._commit_successor_fixture(
                repository_root, "intermediate non-atomic commit"
            )

        seam_b = {
            "seam_id": "SEAM-SUCCESSOR-B",
            "path_pattern": path,
            "authorization_adr_ref": successor_adr_ref,
            "authorization_commit": successor_authorization_commit,
            "authorization_base_commit": successor_authorization_commit,
            "authorization_blob_hash": successor_authorization_hash,
            "allowed_classifications": ["integration"],
            "required_protector_tests": [successor_test_ref],
            "reason": "Admit the exact successor fixture generation.",
        }
        record_b = copy.deepcopy(record_a)
        record_b.update(
            {
                "id": successor_record_id,
                "seam_id": "SEAM-SUCCESSOR-B",
                "patched_blob_hash": self._successor_fixture_hash(b_bytes),
                "protector_tests": [successor_test_ref],
                "reason": "Wire the exact successor fixture seam.",
                "last_revalidated_at": "2026-07-20T00:02:00Z",
            }
        )
        if canonical_identity_drift:
            record_b["base_blob_hash"] = self._successor_fixture_hash(
                b"DIFFERENT-UPSTREAM-BASE\n"
            )
        owner_b = {
            "id": successor_owner_id,
            "classification": successor_owner_classification,
            "paths": [path],
            "requirements": ["PLT-004"],
            "reason": "Own the exact successor fixture seam generation.",
            "verification": [successor_test_ref],
        }
        policy_b = copy.deepcopy(empty_policy)
        policy_b["seams"] = [seam_b]
        entries_b = [owner_b, owner_a] if double_ownership else [owner_b]
        target_path.write_bytes(b_bytes)
        self._write_successor_fixture_json(policy_path, policy_b)
        self._write_successor_fixture_json(
            ledger_path,
            {"upstream_patch_records": [record_b], "entries": entries_b},
        )
        self._commit_successor_fixture(
            repository_root, "replace seam record owner and path bytes atomically"
        )
        return {
            "path": path,
            "policy": policy_b,
            "records": [record_b],
            "entries": entries_b,
            "upstream_commit": upstream_commit,
            "protected_base": successor_authorization_commit,
            "empty_policy_commit": normal_authorization_commit,
            "normal_activation_commit": normal_activation_commit,
        }

    def _activate_third_successor_generation(
        self, repository_root: Path, fixture: dict[str, object]
    ) -> dict[str, object]:
        path = fixture["path"]
        policy_b = fixture["policy"]
        records_b = fixture["records"]
        entries_b = fixture["entries"]
        self.assertIsInstance(path, str)
        self.assertIsInstance(policy_b, dict)
        self.assertIsInstance(records_b, list)
        self.assertIsInstance(entries_b, list)
        seam_b = policy_b["seams"][0]
        record_b = records_b[0]
        owner_b = entries_b[0]
        target_path = repository_root / path
        c_bytes = b"PATCH-C\n"
        successor_adr_ref = "pmorg/adr/ADR-SUCCESSOR-C.json"
        successor_test_ref = (
            "pmorg/tests/test_successor_c.py::TestProtector.test_exact_target"
        )
        successor_test_path = repository_root / successor_test_ref.partition("::")[0]
        successor_test_source = (
            "import unittest\n\n"
            "class TestProtector(unittest.TestCase):\n"
            "    def test_exact_target(self) -> None:\n"
            f"        self.assertEqual((REPOSITORY_ROOT / {path!r}).read_bytes(), "
            f"{c_bytes!r})\n"
        )
        successor_test_path.write_text(successor_test_source, encoding="utf-8")
        successor_authorization = {
            "schema_version": "pmorg.platform.seam-successor-authorization/v1",
            "decision_id": "ADR-SUCCESSOR-C",
            "status": "accepted",
            "specification_commit": self.ledger["specification_commit"],
            "seam_id": "SEAM-SUCCESSOR-C",
            "path": path,
            "allowed_classifications": ["integration"],
            "required_protector_tests": [successor_test_ref],
            "protector_test_hashes": {
                successor_test_ref: self._successor_fixture_hash(
                    successor_test_path.read_bytes()
                )
            },
            "authorized_at": "2026-07-20T00:03:00Z",
            "rationale": "Authorize a third exact successor generation.",
            "transition_id": "TRANSITION-SUCCESSOR-B-C",
            "supersedes": {
                "seam_id": seam_b["seam_id"],
                "patch_record_id": record_b["id"],
                "ledger_entry_id": owner_b["id"],
                "patched_blob_hash": record_b["patched_blob_hash"],
                "patched_git_mode": record_b["patched_git_mode"],
                "authorization_adr_ref": seam_b["authorization_adr_ref"],
                "authorization_blob_hash": seam_b["authorization_blob_hash"],
            },
            "successor_patch_record_id": "UP-SUCCESSOR-C",
            "successor_ledger_entry_id": "PL-SUCCESSOR-C",
            "target_blob_hash": self._successor_fixture_hash(c_bytes),
            "target_git_mode": "100644",
        }
        successor_adr_path = repository_root / successor_adr_ref
        self._write_successor_fixture_json(successor_adr_path, successor_authorization)
        successor_authorization_commit = self._commit_successor_fixture(
            repository_root, "bootstrap third successor authorization"
        )
        successor_authorization_hash = self._successor_fixture_hash(
            successor_adr_path.read_bytes()
        )

        seam_c = copy.deepcopy(seam_b)
        seam_c.update(
            {
                "seam_id": "SEAM-SUCCESSOR-C",
                "authorization_adr_ref": successor_adr_ref,
                "authorization_commit": successor_authorization_commit,
                "authorization_base_commit": successor_authorization_commit,
                "authorization_blob_hash": successor_authorization_hash,
                "required_protector_tests": [successor_test_ref],
                "reason": "Admit the third exact successor generation.",
            }
        )
        record_c = copy.deepcopy(record_b)
        record_c.update(
            {
                "id": "UP-SUCCESSOR-C",
                "seam_id": "SEAM-SUCCESSOR-C",
                "patched_blob_hash": self._successor_fixture_hash(c_bytes),
                "protector_tests": [successor_test_ref],
                "reason": "Wire the third exact successor generation.",
                "last_revalidated_at": "2026-07-20T00:04:00Z",
            }
        )
        owner_c = {
            "id": "PL-SUCCESSOR-C",
            "classification": "integration",
            "paths": [path],
            "requirements": ["PLT-004"],
            "reason": "Own the third exact successor generation.",
            "verification": [successor_test_ref],
        }
        policy_c = copy.deepcopy(policy_b)
        policy_c["seams"] = [seam_c]
        target_path.write_bytes(c_bytes)
        self._write_successor_fixture_json(
            repository_root / "pmorg/policies/seam-allowlist.json", policy_c
        )
        self._write_successor_fixture_json(
            repository_root / "pmorg/patch-ledger.json",
            {"upstream_patch_records": [record_c], "entries": [owner_c]},
        )
        self._commit_successor_fixture(
            repository_root, "activate third exact successor generation"
        )
        return {
            "path": path,
            "policy": policy_c,
            "records": [record_c],
            "entries": [owner_c],
            "upstream_commit": fixture["upstream_commit"],
            "protected_base": successor_authorization_commit,
            "empty_policy_commit": fixture["empty_policy_commit"],
            "normal_activation_commit": fixture["normal_activation_commit"],
        }

    def _validate_successor_fixture(
        self, repository_root: Path, fixture: dict[str, object]
    ) -> tuple[list[str], list[str]]:
        seam_errors = validate_seam_allowlist(
            fixture["policy"],
            repository_root,
            self.ownership_policy,
            repository_root,
            fixture["protected_base"],
        )
        thin_fork_errors = validate_thin_fork_diff(
            [fixture["path"]],
            fixture["entries"],
            fixture["records"],
            self.ownership_policy,
            fixture["policy"],
            repository_root,
            fixture["upstream_commit"],
        )
        return seam_errors, thin_fork_errors

    def test_successor_lifecycle_replaces_seam_record_owner_and_bytes_atomically(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(repository_root)

            self.assertEqual(
                self._validate_successor_fixture(repository_root, fixture), ([], [])
            )

    def test_retired_seam_authorization_and_protector_remain_immutable(self) -> None:
        evidence_cases = {
            "authorization": "pmorg/adr/ADR-SUCCESSOR-A.json",
            "protector": "pmorg/tests/test_successor_a.py",
        }
        for evidence_kind, evidence_ref in evidence_cases.items():
            with self.subTest(evidence_kind=evidence_kind):
                with tempfile.TemporaryDirectory() as directory:
                    repository_root = Path(directory)
                    fixture = self._prepare_successor_lifecycle_repository(
                        repository_root
                    )
                    evidence_path = repository_root / evidence_ref
                    if evidence_kind == "authorization":
                        authorization = json.loads(evidence_path.read_bytes())
                        authorization["rationale"] = (
                            "Mutated after the seam generation was retired."
                        )
                        self._write_successor_fixture_json(evidence_path, authorization)
                    else:
                        evidence_path.write_text(
                            evidence_path.read_text(encoding="utf-8")
                            + "\n# Mutated after retirement.\n",
                            encoding="utf-8",
                        )
                    self._commit_successor_fixture(
                        repository_root, f"mutate retired {evidence_kind} evidence"
                    )

                    seam_errors, _ = self._validate_successor_fixture(
                        repository_root, fixture
                    )

                self.assertTrue(
                    any(
                        error.startswith(
                            "historical seam SEAM-SUCCESSOR-A evidence invalid: "
                        )
                        for error in seam_errors
                    ),
                    seam_errors,
                )

    def test_retired_seam_evidence_cannot_mutate_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(repository_root)
            authorization_path = repository_root / "pmorg/adr/ADR-SUCCESSOR-A.json"
            authorized_bytes = authorization_path.read_bytes()
            authorization = json.loads(authorized_bytes)
            authorization["rationale"] = "Transient mutation before restoration."
            self._write_successor_fixture_json(authorization_path, authorization)
            self._commit_successor_fixture(
                repository_root, "mutate retired authorization evidence"
            )
            authorization_path.write_bytes(authorized_bytes)
            self._commit_successor_fixture(
                repository_root, "restore retired authorization evidence"
            )

            seam_errors, _ = self._validate_successor_fixture(repository_root, fixture)

        self.assertTrue(
            any(
                "historical seam SEAM-SUCCESSOR-A evidence invalid: "
                "authorization ADR pmorg/adr/ADR-SUCCESSOR-A.json changed in "
                "committed history" in error
                for error in seam_errors
            ),
            seam_errors,
        )

    def test_oldest_retired_generation_evidence_is_still_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture_b = self._prepare_successor_lifecycle_repository(repository_root)
            fixture_c = self._activate_third_successor_generation(
                repository_root, fixture_b
            )
            self.assertEqual(
                self._validate_successor_fixture(repository_root, fixture_c), ([], [])
            )
            authorization_path = repository_root / "pmorg/adr/ADR-SUCCESSOR-A.json"
            authorization = json.loads(authorization_path.read_bytes())
            authorization["rationale"] = "Mutation two generations after retirement."
            self._write_successor_fixture_json(authorization_path, authorization)
            self._commit_successor_fixture(
                repository_root, "mutate oldest retired generation evidence"
            )

            seam_errors, _ = self._validate_successor_fixture(
                repository_root, fixture_c
            )

        self.assertTrue(
            any(
                error.startswith("historical seam SEAM-SUCCESSOR-A evidence invalid: ")
                for error in seam_errors
            ),
            seam_errors,
        )

    def test_retired_successor_keeps_exact_predecessor_record_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture_b = self._prepare_successor_lifecycle_repository(
                repository_root, predecessor_record_id="UP-NOT-THE-PREDECESSOR"
            )
            fixture_c = self._activate_third_successor_generation(
                repository_root, fixture_b
            )

            seam_errors, _ = self._validate_successor_fixture(
                repository_root, fixture_c
            )

        self.assertTrue(
            any(
                "historical seam[1] patch record successor binds the wrong "
                "predecessor record" in error
                for error in seam_errors
            ),
            seam_errors,
        )

    def test_retired_successor_keeps_semantically_valid_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture_b = self._prepare_successor_lifecycle_repository(
                repository_root, successor_owner_classification="temporary"
            )
            fixture_c = self._activate_third_successor_generation(
                repository_root, fixture_b
            )

            seam_errors, _ = self._validate_successor_fixture(
                repository_root, fixture_c
            )

        self.assertIn(
            "historical seam[1] ledger owner classification differs from patch record",
            seam_errors,
        )

    def test_retired_successor_keeps_direct_authorization_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture_b = self._prepare_successor_lifecycle_repository(
                repository_root, add_intermediate_commit=True
            )
            fixture_c = self._activate_third_successor_generation(
                repository_root, fixture_b
            )

            seam_errors, _ = self._validate_successor_fixture(
                repository_root, fixture_c
            )

        self.assertTrue(
            any(
                "historical seam[1] authorization base is not its introduction "
                "parent" in error
                for error in seam_errors
            ),
            seam_errors,
        )

    def test_generation_path_and_record_cannot_mutate_and_restore(self) -> None:
        mutation_cases = ("path", "record")
        for mutation_kind in mutation_cases:
            with self.subTest(mutation_kind=mutation_kind):
                with tempfile.TemporaryDirectory() as directory:
                    repository_root = Path(directory)
                    fixture_b = self._prepare_successor_lifecycle_repository(
                        repository_root
                    )
                    if mutation_kind == "path":
                        governed_path = repository_root / fixture_b["path"]
                        generation_bytes = governed_path.read_bytes()
                        governed_path.write_bytes(b"TRANSIENT-UNAUTHORIZED\n")
                        self._commit_successor_fixture(
                            repository_root, "mutate active generation path"
                        )
                        governed_path.write_bytes(generation_bytes)
                    else:
                        ledger_path = repository_root / "pmorg/patch-ledger.json"
                        generation_bytes = ledger_path.read_bytes()
                        ledger = json.loads(generation_bytes)
                        ledger["upstream_patch_records"][0]["base_blob_hash"] = (
                            self._successor_fixture_hash(b"TRANSIENT-BASE\n")
                        )
                        self._write_successor_fixture_json(ledger_path, ledger)
                        self._commit_successor_fixture(
                            repository_root, "mutate active generation record"
                        )
                        ledger_path.write_bytes(generation_bytes)
                    self._commit_successor_fixture(
                        repository_root, f"restore active generation {mutation_kind}"
                    )
                    fixture_c = self._activate_third_successor_generation(
                        repository_root, fixture_b
                    )

                    seam_errors, _ = self._validate_successor_fixture(
                        repository_root, fixture_c
                    )

                expected = (
                    "historical seam SEAM-SUCCESSOR-B path bytes or mode changed "
                    "before retirement"
                    if mutation_kind == "path"
                    else "historical seam SEAM-SUCCESSOR-B patch record changed "
                    "before retirement"
                )
                self.assertTrue(
                    any(expected in error for error in seam_errors), seam_errors
                )

    def test_active_seam_cannot_retire_and_resurrect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(repository_root)
            policy_path = repository_root / "pmorg/policies/seam-allowlist.json"
            empty_policy = copy.deepcopy(fixture["policy"])
            empty_policy["seams"] = []
            self._write_successor_fixture_json(policy_path, empty_policy)
            self._commit_successor_fixture(
                repository_root, "retire active seam without successor"
            )
            self._write_successor_fixture_json(policy_path, fixture["policy"])
            self._commit_successor_fixture(repository_root, "resurrect active seam")

            seam_errors, _ = self._validate_successor_fixture(repository_root, fixture)

        self.assertTrue(
            any(
                "historical seam retired without exact atomic successor" in error
                and error.endswith(": SEAM-SUCCESSOR-B")
                for error in seam_errors
            ),
            seam_errors,
        )
        self.assertTrue(
            any(
                "historical seam ID resurrected" in error
                and error.endswith(": SEAM-SUCCESSOR-B")
                for error in seam_errors
            ),
            seam_errors,
        )

    def test_merge_of_stale_branch_does_not_fabricate_seam_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(repository_root)
            current_branch = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                [
                    "git",
                    "switch",
                    "-q",
                    "-c",
                    "stale-policy-branch",
                    fixture["empty_policy_commit"],
                ],
                cwd=repository_root,
                check=True,
            )
            (repository_root / "stale-only.txt").write_text(
                "unrelated stale-branch change\n", encoding="utf-8"
            )
            self._commit_successor_fixture(
                repository_root, "commit unrelated stale-branch change"
            )
            subprocess.run(
                ["git", "switch", "-q", current_branch],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "merge",
                    "-q",
                    "--no-ff",
                    "stale-policy-branch",
                    "-m",
                    "merge unrelated stale branch",
                ],
                cwd=repository_root,
                check=True,
            )

            self.assertEqual(
                self._validate_successor_fixture(repository_root, fixture), ([], [])
            )

    def test_stale_generation_branch_cannot_hide_path_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(repository_root)
            current_branch = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                [
                    "git",
                    "switch",
                    "-q",
                    "-c",
                    "stale-a-generation",
                    fixture["normal_activation_commit"],
                ],
                cwd=repository_root,
                check=True,
            )
            (repository_root / fixture["path"]).write_bytes(b"STALE-A-UNAUTHORIZED\n")
            self._commit_successor_fixture(
                repository_root, "mutate path on stale A generation"
            )
            subprocess.run(
                ["git", "switch", "-q", current_branch],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "merge",
                    "-q",
                    "--no-ff",
                    "-s",
                    "ours",
                    "stale-a-generation",
                    "-m",
                    "merge stale A history without its tree",
                ],
                cwd=repository_root,
                check=True,
            )

            seam_errors, _ = self._validate_successor_fixture(repository_root, fixture)

        self.assertTrue(
            any(
                "historical seam SEAM-SUCCESSOR-A path bytes or mode changed "
                "before retirement" in error
                for error in seam_errors
            ),
            seam_errors,
        )

    def test_successor_lifecycle_rejects_wrong_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(
                repository_root, predecessor_seam_id="SEAM-SUCCESSOR-WRONG"
            )

            seam_errors, _ = self._validate_successor_fixture(repository_root, fixture)

        self.assertIn(
            "seam[0] successor binds the wrong active predecessor", seam_errors
        )

    def test_normal_v1_authorization_cannot_replace_active_same_path_seam(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(
                repository_root, successor_authorized=False
            )

            seam_errors, _ = self._validate_successor_fixture(repository_root, fixture)

        self.assertIn(
            "same-path seam replacement is not successor-authorized: SEAM-SUCCESSOR-A",
            seam_errors,
        )
        self.assertIn(
            "new seam on occupied protected-base path requires successor "
            "authorization: SEAM-SUCCESSOR-B",
            seam_errors,
        )

    def test_successor_activation_rejects_intermediate_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(
                repository_root, add_intermediate_commit=True
            )

            seam_errors, _ = self._validate_successor_fixture(repository_root, fixture)

        self.assertIn(
            "seam[0] new seam must be introduced atomically on protected PR base",
            seam_errors,
        )

    def test_successor_activation_rejects_replayed_record_and_owner_ids(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(
                repository_root, replay_record_and_owner_ids=True
            )

            _, thin_fork_errors = self._validate_successor_fixture(
                repository_root, fixture
            )

        self.assertIn(
            "UP-SUCCESSOR-A patch record ID existed before atomic seam commit",
            thin_fork_errors,
        )
        self.assertIn(
            "UP-SUCCESSOR-A ledger owner ID existed before atomic seam commit",
            thin_fork_errors,
        )
        self.assertIn(
            "UP-SUCCESSOR-A successor ledger owner ID was reused",
            thin_fork_errors,
        )

    def test_successor_activation_rejects_double_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(
                repository_root, double_ownership=True
            )

            _, thin_fork_errors = self._validate_successor_fixture(
                repository_root, fixture
            )

        self.assertIn(
            "multiply-owned upstream fork path: backend/onyx/example.py "
            "(PL-SUCCESSOR-B, PL-SUCCESSOR-A)",
            thin_fork_errors,
        )

    def test_successor_activation_rejects_unauthorized_target_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(
                repository_root, target_hash_mismatch=True
            )

            _, thin_fork_errors = self._validate_successor_fixture(
                repository_root, fixture
            )

        self.assertIn(
            "UP-SUCCESSOR-B successor patched bytes differ from authorized target",
            thin_fork_errors,
        )

    def test_successor_activation_rejects_canonical_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            fixture = self._prepare_successor_lifecycle_repository(
                repository_root, canonical_identity_drift=True
            )

            _, thin_fork_errors = self._validate_successor_fixture(
                repository_root, fixture
            )

        self.assertIn(
            "UP-SUCCESSOR-B successor changes canonical predecessor field: "
            "base_blob_hash",
            thin_fork_errors,
        )

    def test_static_helm_lane_authorizations_are_byte_bound(self) -> None:
        successor_ref = "pmorg/adr/ADR-0004-helm-static-ephemeral-runner-seam.json"
        normal_ref = "pmorg/adr/ADR-0005-actionlint-helm-lane-label-seam.json"
        successor = json.loads((self.repository_root / successor_ref).read_bytes())
        normal = json.loads((self.repository_root / normal_ref).read_bytes())
        normal_keys = {
            "schema_version",
            "decision_id",
            "status",
            "specification_commit",
            "seam_id",
            "path",
            "allowed_classifications",
            "required_protector_tests",
            "protector_test_hashes",
            "authorized_at",
            "rationale",
        }
        successor_keys = normal_keys | {
            "transition_id",
            "supersedes",
            "successor_patch_record_id",
            "successor_ledger_entry_id",
            "target_blob_hash",
            "target_git_mode",
        }
        predecessor_keys = {
            "seam_id",
            "patch_record_id",
            "ledger_entry_id",
            "patched_blob_hash",
            "patched_git_mode",
            "authorization_adr_ref",
            "authorization_blob_hash",
        }

        self.assertEqual(
            successor["schema_version"],
            "pmorg.platform.seam-successor-authorization/v1",
        )
        self.assertEqual(
            normal["schema_version"], "pmorg.platform.seam-authorization/v1"
        )
        self.assertEqual(set(successor), successor_keys)
        self.assertEqual(set(normal), normal_keys)
        self.assertEqual(set(successor["supersedes"]), predecessor_keys)

        expected_artifacts = [
            (
                successor,
                "pmorg/tests/test_helm_static_lane_ci_seam_protector.py::"
                "TestHelmStaticRunnerAdmissionSeam."
                "test_static_ephemeral_lane_replaces_only_runner_selector",
                "sha256:d7958f9b1f6dcbeaab02fe3eed3876cba82a3cfd0ace2ae04153de9f0965c40f",
                "pmorg/tests/fixtures/ci-seams/pr-helm-chart-testing-static-lane.yml",
                "sha256:49b0a6bc14679eec0780792935a84032504e4c69f068e48a486d1dbf978eeae5",
            ),
            (
                normal,
                "pmorg/tests/test_actionlint_helm_lane_seam_protector.py::"
                "TestActionlintHelmLaneAdmissionSeam."
                "test_helm_lane_is_only_runner_catalog_change",
                "sha256:6a2df969c71c46f4767308cc4546b95be31942fab5e954acba662bae093737e6",
                "pmorg/tests/fixtures/ci-seams/actionlint-static-helm-lane.yml",
                "sha256:4301dbacaf4e7ee2e3b6e88a18c7600a2d716728b16e5c412521c6641daf77e7",
            ),
        ]
        for (
            authorization,
            selector,
            protector_hash,
            fixture_ref,
            fixture_hash,
        ) in expected_artifacts:
            protector_ref, _, _ = selector.partition("::")
            protector_bytes = (self.repository_root / protector_ref).read_bytes()
            fixture_bytes = (self.repository_root / fixture_ref).read_bytes()
            self.assertEqual(authorization["required_protector_tests"], [selector])
            self.assertEqual(
                authorization["protector_test_hashes"], {selector: protector_hash}
            )
            self.assertEqual(
                self._successor_fixture_hash(protector_bytes), protector_hash
            )
            self.assertEqual(self._successor_fixture_hash(fixture_bytes), fixture_hash)
            self.assertIn(
                fixture_hash.removeprefix("sha256:"),
                protector_bytes.decode("utf-8"),
            )

        self.assertEqual(successor["target_blob_hash"], expected_artifacts[0][4])
        seam_ids = frozenset(seam["seam_id"] for seam in self.seam_policy["seams"])
        patch_record_ids = frozenset(
            record["id"] for record in self.ledger["upstream_patch_records"]
        )
        complete_lane_states = {
            (
                frozenset({"SEAM-CI-ZIZMOR-001", "SEAM-CI-HELM-001"}),
                frozenset({"UP-CI-ZIZMOR-001", "UP-CI-HELM-001"}),
            ),
            (
                frozenset(
                    {
                        "SEAM-CI-ZIZMOR-001",
                        "SEAM-CI-HELM-002",
                        "SEAM-CI-ACTIONLINT-001",
                    }
                ),
                frozenset(
                    {
                        "UP-CI-ZIZMOR-001",
                        "UP-CI-HELM-002",
                        "UP-CI-ACTIONLINT-001",
                    }
                ),
            ),
        }

        self.assertIn((seam_ids, patch_record_ids), complete_lane_states)

    def test_current_policy_documents_are_valid_and_default_deny(self) -> None:
        self.assertEqual(validate_patch_ledger_contract(self.ledger), [])
        self.assertEqual(validate_ownership_roots(self.ownership_policy), [])
        self.assertEqual(
            validate_seam_allowlist(
                self.seam_policy, self.repository_root, self.ownership_policy
            ),
            [],
        )
        self.assertEqual(self.ownership_policy["default_ownership"], "upstream_owned")
        self.assertEqual(self.seam_policy["default_decision"], "deny")
        seam_state = tuple(
            (seam["seam_id"], seam["path_pattern"])
            for seam in self.seam_policy["seams"]
        )
        patch_record_state = tuple(
            (record["id"], record["seam_id"], record["path"])
            for record in self.ledger["upstream_patch_records"]
        )
        dormant_state = (
            (
                ("SEAM-CI-ZIZMOR-001", ".github/workflows/zizmor.yml"),
                (
                    "SEAM-CI-HELM-001",
                    ".github/workflows/pr-helm-chart-testing.yml",
                ),
            ),
            (
                (
                    "UP-CI-ZIZMOR-001",
                    "SEAM-CI-ZIZMOR-001",
                    ".github/workflows/zizmor.yml",
                ),
                (
                    "UP-CI-HELM-001",
                    "SEAM-CI-HELM-001",
                    ".github/workflows/pr-helm-chart-testing.yml",
                ),
            ),
        )
        active_state = (
            (
                ("SEAM-CI-ZIZMOR-001", ".github/workflows/zizmor.yml"),
                (
                    "SEAM-CI-HELM-002",
                    ".github/workflows/pr-helm-chart-testing.yml",
                ),
                ("SEAM-CI-ACTIONLINT-001", ".github/actionlint.yml"),
            ),
            (
                (
                    "UP-CI-ZIZMOR-001",
                    "SEAM-CI-ZIZMOR-001",
                    ".github/workflows/zizmor.yml",
                ),
                (
                    "UP-CI-HELM-002",
                    "SEAM-CI-HELM-002",
                    ".github/workflows/pr-helm-chart-testing.yml",
                ),
                (
                    "UP-CI-ACTIONLINT-001",
                    "SEAM-CI-ACTIONLINT-001",
                    ".github/actionlint.yml",
                ),
            ),
        )

        self.assertIn(
            (seam_state, patch_record_state),
            {dormant_state, active_state},
        )

    def test_trusted_protector_ignores_candidate_imports_and_reads_candidate_root(
        self,
    ) -> None:
        protector_source = (
            "from pathlib import Path\n"
            "import unittest\n\n"
            "class TestProtector(unittest.TestCase):\n"
            "    def test_exact_seam(self) -> None:\n"
            "        self.assertEqual(\n"
            "            (REPOSITORY_ROOT / 'inspection-target.txt').read_text(encoding='utf-8'),\n"
            "            'candidate\\n',\n"
            "        )\n"
        )
        with tempfile.TemporaryDirectory() as candidate_directory:
            with tempfile.TemporaryDirectory() as trusted_directory:
                repository_root = Path(candidate_directory)
                trusted_root = Path(trusted_directory)
                sentinel = trusted_root / "candidate-imported"
                (repository_root / "inspection-target.txt").write_text(
                    "candidate\n", encoding="utf-8"
                )
                policy = copy.deepcopy(self.test_seam_policy)
                protected_base = self.prepare_authorization_repository(
                    repository_root, policy, protector_source=protector_source
                )
                test_path_text, _, selector = self.protector_ref.partition("::")
                trusted_test_path = trusted_root / test_path_text
                trusted_test_path.parent.mkdir(parents=True)
                trusted_test_path.write_text(protector_source, encoding="utf-8")
                (trusted_root / "inspection-target.txt").write_text(
                    "trusted\n", encoding="utf-8"
                )
                (repository_root / "pmorg/__init__.py").write_text(
                    "from pathlib import Path\n"
                    f"Path({str(sentinel)!r}).write_text('package import ran')\n",
                    encoding="utf-8",
                )

                with mock.patch.dict(
                    os.environ,
                    {"PMORG_PROTECTED_BASE_SHA": protected_base},
                    clear=False,
                ):
                    self.assertEqual(
                        validate_seam_allowlist(
                            policy,
                            repository_root,
                            self.ownership_policy,
                            trusted_root,
                        ),
                        [],
                    )
                self.assertFalse(sentinel.exists())

                (repository_root / "inspection-target.txt").write_text(
                    "wrong\n", encoding="utf-8"
                )
                self.assertFalse(
                    protector_test_executes_exactly_once(
                        repository_root, trusted_root, test_path_text, selector
                    )
                )

    def test_candidate_protector_top_level_code_is_not_executed_before_auth_checks(
        self,
    ) -> None:
        benign_source = (
            "import unittest\n\n"
            "class TestProtector(unittest.TestCase):\n"
            "    def test_exact_seam(self) -> None:\n"
            "        pass\n"
        )
        with tempfile.TemporaryDirectory() as candidate_directory:
            with tempfile.TemporaryDirectory() as trusted_directory:
                repository_root = Path(candidate_directory)
                trusted_root = Path(trusted_directory)
                sentinel = trusted_root / "candidate-test-imported"
                policy = copy.deepcopy(self.test_seam_policy)
                protected_base = self.prepare_authorization_repository(
                    repository_root, policy, protector_source=benign_source
                )
                test_path_text, _, _ = self.protector_ref.partition("::")
                trusted_test_path = trusted_root / test_path_text
                trusted_test_path.parent.mkdir(parents=True)
                trusted_test_path.write_text(benign_source, encoding="utf-8")
                (repository_root / test_path_text).write_text(
                    "from pathlib import Path\n"
                    f"Path({str(sentinel)!r}).write_text('test import ran')\n"
                    + benign_source,
                    encoding="utf-8",
                )

                with mock.patch.dict(
                    os.environ,
                    {"PMORG_PROTECTED_BASE_SHA": protected_base},
                    clear=False,
                ):
                    errors = validate_seam_allowlist(
                        policy,
                        repository_root,
                        self.ownership_policy,
                        trusted_root,
                    )

        self.assertFalse(sentinel.exists())
        self.assertIn("seam[0] protector test changed after authorization", errors)

    def test_governed_admission_invariant_cannot_be_flipped(self) -> None:
        policy = copy.deepcopy(self.seam_policy)
        policy["invariants"]["governed_integration_admission_required"] = False

        self.assertIn(
            "seam allowlist invariants are incomplete",
            validate_seam_allowlist(policy),
        )

    def test_policy_documents_reject_unknown_top_level_fields(self) -> None:
        ownership_policy = copy.deepcopy(self.ownership_policy)
        ownership_policy["bypass"] = True
        self.assertIn(
            "ownership roots policy has incomplete or unknown fields",
            validate_ownership_roots(ownership_policy),
        )

        seam_policy = copy.deepcopy(self.seam_policy)
        seam_policy["bypass"] = True
        self.assertIn(
            "seam allowlist has incomplete or unknown fields",
            validate_seam_allowlist(seam_policy),
        )

        ledger = copy.deepcopy(self.ledger)
        ledger["bypass"] = True
        self.assertIn(
            "patch ledger has incomplete or unknown top-level fields",
            validate_patch_ledger_contract(ledger),
        )

    def test_current_pmorg_owned_paths_are_exactly_ledger_covered(self) -> None:
        paths = [
            "PMORG.md",
            ".github/workflows/pmorg-governance.yml",
            ".codex/agents/pmorg-implementer.toml",
            "plans/pmorg-v3-foundation.md",
            "pmorg/baseline-manifest.json",
            "pmorg/policies/ownership-roots.json",
            "pmorg/policies/seam-allowlist.json",
            "pmorg/adr/ADR-0001-governed-integration-admission.md",
            "pmorg/scripts/verify_fork.py",
            "pmorg/tests/test_verify_fork.py",
        ]

        self.assertEqual(
            validate_thin_fork_diff(
                paths,
                self.ledger["entries"],
                [],
                self.ownership_policy,
                self.seam_policy,
            ),
            [],
        )

    def test_plt_008_trace_is_mandatory_in_patch_ledger(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        for entry in ledger["entries"]:
            entry["requirements"] = [
                requirement
                for requirement in entry["requirements"]
                if requirement != "PLT-008"
            ]

        self.assertIn(
            "patch ledger does not trace required platform requirements: PLT-008",
            validate_patch_ledger_contract(ledger),
        )

    def test_ownership_root_set_cannot_be_broadened(self) -> None:
        policy = copy.deepcopy(self.ownership_policy)
        policy["roots"].append(
            {
                "root_id": "unsafe-broad-root",
                "path_pattern": "backend/**",
                "ownership": "pmorg_owned",
            }
        )

        self.assertIn(
            "ownership root set must remain the exact reviewed governed boundary",
            validate_ownership_roots(policy),
        )

    def test_bounded_product_roots_require_a_ledger_owner(self) -> None:
        entries = copy.deepcopy(self.ledger["entries"])
        entries.append(
            {
                "id": "PL-TEST-DOMAIN",
                "classification": "PMORG-owned",
                "paths": ["backend/pmorg/domain.py", "web/src/pmorg/view.tsx"],
                "requirements": ["PLT-004"],
                "reason": "Own simulated bounded PMORG product paths.",
                "verification": [self.protector_ref],
            }
        )
        self.assertEqual(
            validate_thin_fork_diff(
                ["backend/pmorg/domain.py", "web/src/pmorg/view.tsx"],
                entries,
                [],
                self.ownership_policy,
                self.seam_policy,
            ),
            [],
        )

    def test_pmorg_owned_path_requires_pmorg_owned_ledger_classification(self) -> None:
        entries = copy.deepcopy(self.ledger["entries"])
        entries[0]["classification"] = "integration"

        self.assertIn(
            "PMORG-owned path must use PMORG-owned ledger classification: "
            "pmorg/baseline-manifest.json",
            validate_thin_fork_diff(
                ["pmorg/baseline-manifest.json"],
                entries,
                [],
                self.ownership_policy,
                self.seam_policy,
            ),
        )

    def test_upstream_owned_change_without_seam_and_record_is_denied(self) -> None:
        errors = validate_thin_fork_diff(
            ["backend/onyx/example.py"],
            self.ledger["entries"],
            [],
            self.ownership_policy,
            self.seam_policy,
        )

        self.assertEqual(
            errors,
            [
                "uncovered upstream-owned fork path: backend/onyx/example.py",
                "upstream-owned path requires exactly one allowlisted seam: backend/onyx/example.py",
            ],
        )

    def test_governed_allowlisted_change_with_exact_record_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root, policy
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                self.assertEqual(
                    validate_seam_allowlist(
                        policy,
                        repository_root,
                        self.ownership_policy,
                    ),
                    [],
                )
        self.assertEqual(
            validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.integration_entries,
                [self.valid_upstream_record],
                self.ownership_policy,
                self.test_seam_policy,
                upstream_commit=self.ledger["upstream_commit"],
            ),
            [],
        )

    def test_legacy_slice_zero_policy_cannot_admit_a_patch(self) -> None:
        policy = copy.deepcopy(self.test_seam_policy)
        policy["schema_version"] = "pmorg.platform.seam-allowlist/v1"
        policy.pop("admission_mode")

        self.assertIn(
            "upstream-owned changes require governed integration admission: "
            "backend/onyx/example.py",
            validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.integration_entries,
                [self.valid_upstream_record],
                self.ownership_policy,
                policy,
                upstream_commit=self.ledger["upstream_commit"],
            ),
        )

    def test_allowlisted_upstream_change_without_record_is_denied(self) -> None:
        self.assertIn(
            "upstream-owned path requires exactly one upstream patch record: "
            "backend/onyx/example.py",
            validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.integration_entries,
                [],
                self.ownership_policy,
                self.test_seam_policy,
            ),
        )

    def test_seam_requires_safe_existing_accepted_adr(self) -> None:
        policy = copy.deepcopy(self.test_seam_policy)
        policy["seams"][0]["authorization_adr_ref"] = "pmorg/adr/missing.json"
        errors = validate_seam_allowlist(
            policy, self.repository_root, self.ownership_policy
        )
        self.assertIn("seam[0] authorization ADR does not exist", errors)

        policy["seams"][0]["authorization_adr_ref"] = "pmorg/PATCH-LEDGER.md"
        errors = validate_seam_allowlist(
            policy, self.repository_root, self.ownership_policy
        )
        self.assertIn("seam[0] authorization ADR must live under pmorg/adr", errors)
        self.assertIn("seam[0] authorization ADR must be machine-readable JSON", errors)
        self.assertIn("seam[0] authorization ADR is not a valid JSON object", errors)

    def test_seam_requires_safe_existing_protector_test(self) -> None:
        policy = copy.deepcopy(self.test_seam_policy)
        policy["seams"][0]["required_protector_tests"] = [
            "pmorg/tests/test_missing.py::MissingTest.test_missing"
        ]
        self.protector_ref = policy["seams"][0]["required_protector_tests"][0]
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            protected_base = self.prepare_authorization_repository(
                repository_root, policy, write_protector=False
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )
        self.assertIn("seam[0] protector test file does not exist", errors)
        self.assertIn(
            "seam[0] protector test was absent at authorization_commit", errors
        )

    def test_seam_path_must_be_exact(self) -> None:
        policy = copy.deepcopy(self.test_seam_policy)
        policy["seams"][0]["path_pattern"] = "backend/onyx/**"
        self.assertIn(
            "seam[0] path_pattern must be a safe exact path",
            validate_seam_allowlist(policy),
        )

    def test_generic_transition_adr_cannot_authorize_a_concrete_seam(self) -> None:
        policy = copy.deepcopy(self.test_seam_policy)
        policy["seams"][0]["authorization_adr_ref"] = (
            "pmorg/adr/ADR-0001-governed-integration-admission.md"
        )

        errors = validate_seam_allowlist(
            policy, self.repository_root, self.ownership_policy
        )

        self.assertIn("seam[0] authorization ADR must be machine-readable JSON", errors)

    def test_authorization_binds_exact_seam_and_valid_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root,
                policy,
                authorization_overrides={
                    "path": "backend/onyx/another.py",
                    "authorized_at": "2026-02-30T10:00:00Z",
                },
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn("seam[0] authorization ADR binds another path", errors)
        self.assertIn("seam[0] authorization ADR authorized_at is not UTC", errors)

    def test_authorization_and_protector_bytes_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root, policy
            )
            (repository_root / self.adr_ref).write_text("{}\n", encoding="utf-8")
            protector_path_text, _, _ = self.protector_ref.partition("::")
            (repository_root / protector_path_text).write_text(
                "import unittest\n\n"
                "class TestProtector(unittest.TestCase):\n"
                "    def test_exact_seam(self) -> None:\n"
                "        raise AssertionError\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn("seam[0] authorization ADR changed after authorization", errors)
        self.assertIn("seam[0] protector test changed after authorization", errors)

    def test_authorization_and_protector_git_modes_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root, policy
            )
            protector_path_text, _, _ = self.protector_ref.partition("::")
            authorization_path = repository_root / self.adr_ref
            protector_path = repository_root / protector_path_text
            authorization_path.chmod(0o755)
            protector_path.chmod(0o755)
            subprocess.run(
                ["git", "add", str(authorization_path), str(protector_path)],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-q", "-m", "change evidence modes"],
                cwd=repository_root,
                check=True,
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn("seam[0] authorization ADR Git mode or type changed", errors)
        self.assertIn("seam[0] protector test Git mode or type changed", errors)

    def test_authorization_evidence_must_exist_on_protected_seam_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root,
                policy,
                delete_and_restore_evidence_on_seam_change=True,
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn(
            "seam[0] authorization ADR was not preserved on protected seam base",
            errors,
        )
        self.assertIn(
            "seam[0] protector test was not preserved on protected seam base",
            errors,
        )

    def test_protector_selector_must_be_a_collectible_python_test(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root,
                policy,
                protector_source=(
                    "class TestProtector:\n"
                    "    def test_exact_seam(self) -> None:\n"
                    "        pass\n"
                ),
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn("seam[0] protector test node does not exist", errors)
        self.assertIn(
            "seam[0] protector test node was absent at authorization_commit", errors
        )

    def test_protector_must_be_inside_governance_discovery_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            self.protector_ref = (
                "pmorg/adr/test_hidden_protector.py::TestProtector.test_exact_seam"
            )
            policy["seams"][0]["required_protector_tests"] = [self.protector_ref]
            protected_base = self.prepare_authorization_repository(
                repository_root, policy
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn(
            "seam[0] protector test is outside governance discovery set", errors
        )

    def test_skipped_protector_test_cannot_authorize_a_seam(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root,
                policy,
                protector_source=(
                    "import unittest\n\n"
                    "class TestProtector(unittest.TestCase):\n"
                    '    @unittest.skip("disabled")\n'
                    "    def test_exact_seam(self) -> None:\n"
                    "        pass\n"
                ),
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn("seam[0] protector test node does not exist", errors)
        self.assertIn(
            "seam[0] protector test node was absent at authorization_commit", errors
        )

    def test_class_level_skip_cannot_authorize_a_seam(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root,
                policy,
                protector_source=(
                    "import unittest\n\n"
                    '@unittest.skip("disabled")\n'
                    "class TestProtector(unittest.TestCase):\n"
                    "    def test_exact_seam(self) -> None:\n"
                    "        pass\n"
                ),
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn(
            "seam[0] protector test did not execute exactly once without skips",
            errors,
        )

    def test_new_seam_requires_trusted_base_and_survives_later_bases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            authorization_base = self.prepare_authorization_repository(
                repository_root, policy
            )
            seam_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            with mock.patch.dict(
                os.environ, {"PMORG_PROTECTED_BASE_SHA": ""}, clear=False
            ):
                branch_errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

            future_marker = repository_root / "future-change.txt"
            future_marker.write_text("later PR\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", str(future_marker)], cwd=repository_root, check=True
            )
            subprocess.run(
                ["git", "commit", "-q", "-m", "later change"],
                cwd=repository_root,
                check=True,
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": seam_commit},
                clear=False,
            ):
                later_errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

            mutated_policy = copy.deepcopy(policy)
            mutated_policy["seams"][0]["reason"] = "Unreviewed mutation."
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": seam_commit},
                clear=False,
            ):
                mutation_errors = validate_seam_allowlist(
                    mutated_policy, repository_root, self.ownership_policy
                )

        self.assertEqual(
            policy["seams"][0]["authorization_base_commit"], authorization_base
        )
        self.assertIn(
            "seam[0] PMORG_PROTECTED_BASE_SHA is required off origin/main",
            branch_errors,
        )
        self.assertEqual(later_errors, [])
        self.assertIn(
            "seam[0] existing seam is immutable; authorize a new seam_id",
            mutation_errors,
        )

    def test_main_history_proves_seam_was_pre_authorized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            self.prepare_authorization_repository(repository_root, policy)
            subprocess.run(
                ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
                cwd=repository_root,
                check=True,
            )
            with mock.patch.dict(
                os.environ, {"PMORG_PROTECTED_BASE_SHA": ""}, clear=False
            ):
                self.assertEqual(
                    validate_seam_allowlist(
                        policy, repository_root, self.ownership_policy
                    ),
                    [],
                )

    def test_new_seam_must_be_atomic_on_the_protected_base(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            policy = copy.deepcopy(self.test_seam_policy)
            protected_base = self.prepare_authorization_repository(
                repository_root, policy, add_intermediate_commit=True
            )
            with mock.patch.dict(
                os.environ,
                {"PMORG_PROTECTED_BASE_SHA": protected_base},
                clear=False,
            ):
                errors = validate_seam_allowlist(
                    policy, repository_root, self.ownership_policy
                )

        self.assertIn(
            "seam[0] new seam must be introduced atomically on protected PR base",
            errors,
        )

    def test_non_pmorg_ledger_paths_must_not_use_wildcards(self) -> None:
        entries = copy.deepcopy(self.integration_entries)
        entries[-1]["paths"] = ["backend/onyx/**"]

        self.assertIn(
            "PL-TEST-INTEGRATION non-PMORG ledger paths must be exact",
            validate_patch_entries(entries),
        )

    def test_patch_record_protector_set_and_urls_are_exact(self) -> None:
        record = copy.deepcopy(self.valid_upstream_record)
        record["protector_tests"].append("pmorg/tests/test_fake.py::test_fake")
        record["upstream_issue_url"] = (
            "https://github.com/onyx-dot-app/onyx/../../other/issues/1"
        )
        record["upstream_pr_url"] = "https://github.com/onyx-dot-app/onyx/issues/2"

        errors = validate_upstream_patch_record(
            record,
            self.test_seam_policy["seams"][0],
            "UP-TEST",
            expected_upstream_commit=self.ledger["upstream_commit"],
        )

        self.assertIn("UP-TEST protector tests differ from its seam", errors)
        self.assertIn(
            "UP-TEST upstream_issue_url must be an exact official Onyx URL or null",
            errors,
        )
        self.assertIn(
            "UP-TEST upstream_pr_url must be an exact official Onyx URL or null",
            errors,
        )

    def test_patch_record_revalidation_timestamp_is_strict(self) -> None:
        record = copy.deepcopy(self.valid_upstream_record)
        record["last_revalidated_at"] = "not-a-dateTbutZ"

        self.assertIn(
            "UP-TEST last_revalidated_at must be RFC3339 UTC",
            validate_upstream_patch_record(
                record,
                self.test_seam_policy["seams"][0],
                "UP-TEST",
                expected_upstream_commit=self.ledger["upstream_commit"],
            ),
        )

    def test_upstream_seam_patch_cannot_delete_its_path(self) -> None:
        record = copy.deepcopy(self.valid_upstream_record)
        record["patched_blob_hash"] = None
        record["patched_git_mode"] = None

        self.assertIn(
            "UP-TEST upstream seam patch cannot delete its path",
            validate_upstream_patch_record(
                record,
                self.test_seam_policy["seams"][0],
                "UP-TEST",
                expected_upstream_commit=self.ledger["upstream_commit"],
            ),
        )

    def test_record_and_patch_cannot_follow_a_seam_only_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            seam_policy = copy.deepcopy(self.test_seam_policy)
            upstream_commit = self.prepare_authorization_repository(
                repository_root, seam_policy
            )
            tree_bytes = subprocess.run(
                ["git", "ls-tree", "-r", "-z", upstream_commit],
                cwd=repository_root,
                check=True,
                capture_output=True,
            ).stdout
            path = repository_root / "backend/onyx/example.py"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PATCHED = True\n", encoding="utf-8")
            record = copy.deepcopy(self.valid_upstream_record)
            record["base_blob_hash"] = None
            record["base_git_mode"] = None
            record["patched_blob_hash"] = (
                "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            )
            record["upstream_source_ref"]["commit"] = upstream_commit
            record["upstream_source_ref"]["tree_hash"] = (
                "sha256:" + hashlib.sha256(tree_bytes).hexdigest()
            )
            patch_ledger = copy.deepcopy(self.ledger)
            patch_ledger["upstream_commit"] = upstream_commit
            patch_ledger["entries"] = self.integration_entries
            patch_ledger["upstream_patch_records"] = [record]
            ledger_path = repository_root / "pmorg/patch-ledger.json"
            ledger_path.write_text(
                json.dumps(patch_ledger, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=repository_root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "late patch and record"],
                cwd=repository_root,
                check=True,
            )

            errors = validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.integration_entries,
                [record],
                self.ownership_policy,
                seam_policy,
                repository_root,
                upstream_commit,
            )

        self.assertIn(
            "UP-TEST exact patch record was not introduced atomically with seam",
            errors,
        )
        self.assertIn(
            "UP-TEST patched bytes were not introduced atomically with seam", errors
        )

    def test_enterprise_path_cannot_self_classify_as_ce(self) -> None:
        path = "backend/ee/unsafe.py"
        policy = copy.deepcopy(self.test_seam_policy)
        policy["seams"][0]["path_pattern"] = path
        entries = copy.deepcopy(self.integration_entries)
        entries[-1]["paths"] = [path]
        record = copy.deepcopy(self.valid_upstream_record)
        record["path"] = path
        record["upstream_source_ref"]["path"] = path

        errors = validate_thin_fork_diff(
            [path],
            entries,
            [record],
            self.ownership_policy,
            policy,
            upstream_commit=self.ledger["upstream_commit"],
        )

        self.assertIn("UP-TEST Enterprise path cannot claim CE patch ownership", errors)

    def test_tree_digest_and_regular_file_modes_are_bound_to_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=repository_root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=repository_root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "PMORG Test"],
                cwd=repository_root,
                check=True,
            )
            path = repository_root / "backend/onyx/example.py"
            path.parent.mkdir(parents=True)
            path.write_text("BASE = True\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repository_root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "upstream"],
                cwd=repository_root,
                check=True,
            )
            upstream_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tree_bytes = subprocess.run(
                ["git", "ls-tree", "-r", "-z", upstream_commit],
                cwd=repository_root,
                check=True,
                capture_output=True,
            ).stdout
            tree_hash = "sha256:" + hashlib.sha256(tree_bytes).hexdigest()
            base_hash = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

            path.write_text("BASE = False\n", encoding="utf-8")
            patched_hash = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            record = copy.deepcopy(self.valid_upstream_record)
            record["base_blob_hash"] = base_hash
            record["patched_blob_hash"] = patched_hash
            record["upstream_source_ref"]["commit"] = upstream_commit
            record["upstream_source_ref"]["tree_hash"] = tree_hash
            seam_policy = copy.deepcopy(self.test_seam_policy)
            policy_path = repository_root / "pmorg/policies/seam-allowlist.json"
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            policy_path.write_text(
                json.dumps(seam_policy, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            patch_ledger = copy.deepcopy(self.ledger)
            patch_ledger["upstream_commit"] = upstream_commit
            patch_ledger["entries"] = self.integration_entries
            patch_ledger["upstream_patch_records"] = [record]
            ledger_path = repository_root / "pmorg/patch-ledger.json"
            ledger_path.write_text(
                json.dumps(patch_ledger, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=repository_root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "atomic seam patch"],
                cwd=repository_root,
                check=True,
            )

            exact_errors = validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.integration_entries,
                [record],
                self.ownership_policy,
                seam_policy,
                repository_root,
                upstream_commit,
            )

            wrong_tree_record = copy.deepcopy(record)
            wrong_tree_record["upstream_source_ref"]["tree_hash"] = "sha256:" + "9" * 64
            tree_errors = validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.integration_entries,
                [wrong_tree_record],
                self.ownership_policy,
                seam_policy,
                repository_root,
                upstream_commit,
            )

            path.unlink()
            path.symlink_to("../../pmorg/domain.py")
            subprocess.run(["git", "add", str(path)], cwd=repository_root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "symlink patch"],
                cwd=repository_root,
                check=True,
            )
            symlink_record = copy.deepcopy(record)
            symlink_record["patched_blob_hash"] = (
                "sha256:" + hashlib.sha256(os.readlink(path).encode()).hexdigest()
            )
            symlink_record["patched_git_mode"] = "120000"
            symlink_errors = validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.integration_entries,
                [symlink_record],
                self.ownership_policy,
                seam_policy,
                repository_root,
                upstream_commit,
            )

        self.assertEqual(exact_errors, [])
        self.assertIn(
            "UP-TEST upstream_source_ref tree_hash differs from pinned tree",
            tree_errors,
        )
        self.assertIn(
            "UP-TEST patched_git_mode must be a regular-file mode or null",
            symlink_errors,
        )

    def test_record_classification_must_match_ledger_owner(self) -> None:
        entries = copy.deepcopy(self.integration_entries)
        entries[-1]["classification"] = "temporary"
        self.assertIn(
            "UP-TEST classification differs from its ledger owner",
            validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                entries,
                [self.valid_upstream_record],
                self.ownership_policy,
                self.test_seam_policy,
                upstream_commit=self.ledger["upstream_commit"],
            ),
        )

    def test_ee_direct_patch_cannot_claim_ce_or_mit_license(self) -> None:
        record = copy.deepcopy(self.valid_upstream_record)
        record["ownership_class"] = "upstream_ee_direct_patch"
        record["license_class"] = "mit-expat"
        record["onyx_surfaces"] = ["ce", "ee"]

        errors = validate_thin_fork_diff(
            ["backend/onyx/example.py"],
            self.integration_entries,
            [record],
            self.ownership_policy,
            self.test_seam_policy,
            upstream_commit=self.ledger["upstream_commit"],
        )

        self.assertIn(
            "UP-TEST EE direct patch must use onyx-enterprise license_class",
            errors,
        )
        self.assertIn("UP-TEST EE direct patch is forbidden from CE surface", errors)

    def test_non_object_entries_and_records_fail_without_traceback(self) -> None:
        self.assertEqual(
            validate_patch_entries([42]),
            ["entry[0] is not an object"],
        )
        ledger = copy.deepcopy(self.ledger)
        ledger["upstream_patch_records"] = [42]
        self.assertIn(
            "patch ledger upstream_patch_records must contain only objects",
            validate_patch_ledger_contract(ledger),
        )
        self.assertEqual(
            validate_thin_fork_diff(
                [],
                self.ledger["entries"],
                [42],
                self.ownership_policy,
                self.seam_policy,
            ),
            ["upstream_patch_records[0] is not an object"],
        )

        policy = copy.deepcopy(self.test_seam_policy)
        policy["seams"][0]["allowed_classifications"] = [{}]
        self.assertIn(
            "seam[0] has invalid allowed_classifications",
            validate_seam_allowlist(policy),
        )

        record = copy.deepcopy(self.valid_upstream_record)
        record["protector_tests"] = [{}]
        self.assertIn(
            "UP-TEST has invalid protector_tests list",
            validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.integration_entries,
                [record],
                self.ownership_policy,
                self.test_seam_policy,
                upstream_commit=self.ledger["upstream_commit"],
            ),
        )

    def test_pmorg_domain_under_upstream_root_is_fail_closed(self) -> None:
        policy = copy.deepcopy(self.test_seam_policy)
        policy["seams"][0]["path_pattern"] = "backend/onyx/pmorg.py"
        record = copy.deepcopy(self.valid_upstream_record)
        record["path"] = "backend/onyx/pmorg.py"
        record["upstream_source_ref"]["path"] = "backend/onyx/pmorg.py"
        entries = copy.deepcopy(self.integration_entries)
        entries[-1]["paths"] = ["backend/onyx/pmorg.py"]
        errors = validate_thin_fork_diff(
            ["backend/onyx/pmorg.py"],
            entries,
            [record],
            self.ownership_policy,
            policy,
            upstream_commit=self.ledger["upstream_commit"],
        )

        self.assertIn(
            "PMORG domain path is forbidden under an upstream-owned root: "
            "backend/onyx/pmorg.py",
            errors,
        )


if __name__ == "__main__":
    unittest.main()
