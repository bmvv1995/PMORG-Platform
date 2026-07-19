from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from verify_fork import PatchEntry  # noqa: E402
from verify_fork import COMMON_QUALIFICATION_REF_KEYS  # noqa: E402
from verify_fork import find_path_owners  # noqa: E402
from verify_fork import load_manifest  # noqa: E402
from verify_fork import load_ownership_roots  # noqa: E402
from verify_fork import load_patch_ledger  # noqa: E402
from verify_fork import load_seam_allowlist  # noqa: E402
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


class ForkLedgerTest(unittest.TestCase):
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
        self.assertEqual(
            owners["web/src/app/admin/bots/b/channels/i/page.tsx"], []
        )

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
        manifest["round_3_contract"][
            "source_specification_commit"
        ] = alternate_commit

        self.assertIn(
            "baseline is not pinned to the accepted PMORG specification commit",
            validate_round_3_contract(manifest),
        )

    def test_plt_008_and_distribution_contract_cannot_be_removed(self) -> None:
        manifest = copy.deepcopy(load_manifest(self.repository_root))
        manifest["round_3_contract"]["platform_requirements"] = [
            requirement
            for requirement in manifest["round_3_contract"][
                "platform_requirements"
            ]
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
        manifest["round_3_contract"]["qualification_bundle_roles"][
            "common"
        ].remove("capability-evidence-bundle-index")

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
        self.assertTrue(
            all(value == [] for value in build["operation_refs"].values())
        )

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
        manifest["build"]["qualification_refs"][
            "ce_boundary_report_hash"
        ] = digest

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
        manifest["build"]["qualification_refs"][
            "ee_inventory_report_hash"
        ] = digest
        manifest["build"]["operation_refs"][
            "deployment_admission_envelope_hashes"
        ] = [digest]

        errors = validate_build_qualification_state(manifest)

        self.assertTrue(
            any(error.startswith("not_yet_qualified build must keep") for error in errors)
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
        self.ownership_policy = load_ownership_roots(
            self.repository_root, self.ledger
        )
        self.seam_policy = load_seam_allowlist(self.repository_root, self.ledger)
        self.test_seam_policy = copy.deepcopy(self.seam_policy)
        self.test_seam_policy["seams"] = [
            {
                "seam_id": "SEAM-TEST",
                "path_pattern": "backend/onyx/example.py",
                "authorization_adr_ref": "ADR-TEST",
                "allowed_classifications": ["integration"],
                "required_protector_tests": ["test-seam"],
                "reason": "Bounded test seam.",
            }
        ]
        self.valid_upstream_record = {
            "id": "UP-TEST",
            "path": "backend/onyx/example.py",
            "seam_id": "SEAM-TEST",
            "classification": "integration",
            "base_blob_hash": "sha256:" + "1" * 64,
            "patched_blob_hash": "sha256:" + "2" * 64,
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
            "protector_tests": ["test-seam"],
            "last_revalidated_at": "2026-07-19T00:00:00Z",
            "conflict_notes": "none observed",
            "removal_condition": None,
        }

    def test_current_policy_documents_are_valid_and_default_deny(self) -> None:
        self.assertEqual(validate_patch_ledger_contract(self.ledger), [])
        self.assertEqual(validate_ownership_roots(self.ownership_policy), [])
        self.assertEqual(validate_seam_allowlist(self.seam_policy), [])
        self.assertEqual(self.ownership_policy["default_ownership"], "upstream_owned")
        self.assertEqual(self.seam_policy["default_decision"], "deny")

    def test_slice_zero_upstream_forbid_invariant_cannot_be_flipped(self) -> None:
        policy = copy.deepcopy(self.seam_policy)
        policy["invariants"]["slice_zero_upstream_changes_forbidden"] = False

        self.assertIn(
            "seam allowlist invariants are incomplete",
            validate_seam_allowlist(policy),
        )

    def test_current_pmorg_owned_paths_are_exactly_ledger_covered(self) -> None:
        paths = [
            "PMORG.md",
            ".codex/agents/pmorg-implementer.toml",
            "plans/pmorg-v3-foundation.md",
            "pmorg/baseline-manifest.json",
            "pmorg/policies/ownership-roots.json",
            "pmorg/policies/seam-allowlist.json",
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
            "ownership root set must remain the exact reviewed Slice 0 boundary",
            validate_ownership_roots(policy),
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
                "Slice 0 forbids upstream-owned changes until canonical boundary "
                "evidence admission exists: backend/onyx/example.py",
                "upstream-owned path requires exactly one allowlisted seam: backend/onyx/example.py"
            ],
        )

    def test_structurally_complete_upstream_record_is_still_denied_in_slice_zero(self) -> None:
        self.assertIn(
            "Slice 0 seam allowlist must remain empty",
            validate_seam_allowlist(self.test_seam_policy),
        )
        self.assertEqual(
            validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.ledger["entries"],
                [self.valid_upstream_record],
                self.ownership_policy,
                self.test_seam_policy,
                upstream_commit=self.ledger["upstream_commit"],
            ),
            [
                "Slice 0 forbids upstream-owned changes until canonical boundary "
                "evidence admission exists: backend/onyx/example.py"
            ],
        )

    def test_allowlisted_upstream_change_without_record_is_denied(self) -> None:
        self.assertIn(
            "upstream-owned path requires exactly one upstream patch record: "
            "backend/onyx/example.py",
            validate_thin_fork_diff(
                ["backend/onyx/example.py"],
                self.ledger["entries"],
                [],
                self.ownership_policy,
                self.test_seam_policy,
            ),
        )

    def test_ee_direct_patch_cannot_claim_ce_or_mit_license(self) -> None:
        record = copy.deepcopy(self.valid_upstream_record)
        record["ownership_class"] = "upstream_ee_direct_patch"
        record["license_class"] = "mit-expat"
        record["onyx_surfaces"] = ["ce", "ee"]

        errors = validate_thin_fork_diff(
            ["backend/onyx/example.py"],
            self.ledger["entries"],
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

    def test_pmorg_domain_under_upstream_root_is_fail_closed(self) -> None:
        errors = validate_thin_fork_diff(
            ["backend/onyx/pmorg/domain.py"],
            self.ledger["entries"],
            [],
            self.ownership_policy,
            self.seam_policy,
        )

        self.assertIn(
            "upstream-owned path requires exactly one allowlisted seam: "
            "backend/onyx/pmorg/domain.py",
            errors,
        )


if __name__ == "__main__":
    unittest.main()
