from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from typing import cast

from pmorg.application.candidate_search import _candidate_group
from pmorg.application.candidate_search import CandidateSearchError
from pmorg.application.candidate_search import check_candidate_search
from pmorg.application.candidate_search import derive_candidate_search_outputs

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SEARCH_ROOT = REPOSITORY_ROOT / "pmorg" / "capabilities" / "candidate-search"


class TestCandidateSearch(unittest.TestCase):
    def test_committed_search_is_complete_and_deterministic(self) -> None:
        check_candidate_search(REPOSITORY_ROOT)
        first = derive_candidate_search_outputs(REPOSITORY_ROOT)
        second = derive_candidate_search_outputs(REPOSITORY_ROOT)

        self.assertEqual(first, second)
        self.assertEqual(len(first.evidence), 6)
        for capability_id, payload in first.evidence.items():
            evidence = json.loads(payload)
            self.assertEqual(evidence["capability_id"], capability_id)
            self.assertEqual(evidence["searched_surfaces"], ["ce", "ee"])
            self.assertEqual(evidence["expected_path_count"], 5_937)
            self.assertEqual(evidence["scanned_path_count"], 5_937)
            self.assertEqual(evidence["unscanned_path_count"], 0)
            self.assertEqual(evidence["duplicate_path_count"], 0)
            self.assertEqual(evidence["unreadable_path_count"], 0)
            self.assertEqual(evidence["unclassified_hit_count"], 0)
            self.assertEqual(evidence["duplicate_hit_id_count"], 0)

    def test_raw_hits_and_classification_are_byte_closed_and_bijective(self) -> None:
        expected_raw_keys = {
            "candidate_group",
            "content_sha256",
            "git_object_id",
            "hit_id",
            "matched_group_indexes",
            "matched_terms",
            "mode",
            "path",
            "size_bytes",
            "surface",
        }
        for evidence_path in sorted(SEARCH_ROOT.glob("*-search-evidence-v1.json")):
            evidence = json.loads(evidence_path.read_bytes())
            raw = json.loads(
                (
                    REPOSITORY_ROOT / evidence["raw_results"]["relative_path"]
                ).read_bytes()
            )
            classifications = json.loads(
                (
                    REPOSITORY_ROOT / evidence["hit_classification"]["relative_path"]
                ).read_bytes()
            )
            raw_ids = [hit["hit_id"] for hit in raw["hits"]]
            classified_ids = [record["hit_id"] for record in classifications["records"]]
            self.assertEqual(raw_ids, classified_ids)
            self.assertEqual(len(raw_ids), len(set(raw_ids)))
            self.assertEqual(raw["raw_hit_count"], len(raw_ids))
            self.assertEqual(
                classifications["classification_record_count"], len(raw_ids)
            )
            self.assertTrue(all(set(hit) == expected_raw_keys for hit in raw["hits"]))
            self.assertFalse(any("excerpt" in hit for hit in raw["hits"]))

    def test_candidate_ids_are_stable_unique_module_groups_not_verdicts(self) -> None:
        for evidence_path in sorted(SEARCH_ROOT.glob("*-search-evidence-v1.json")):
            evidence = json.loads(evidence_path.read_bytes())
            classifications = json.loads(
                (
                    REPOSITORY_ROOT / evidence["hit_classification"]["relative_path"]
                ).read_bytes()
            )
            candidate_ids = evidence["candidate_ids"]
            self.assertEqual(len(candidate_ids), len(set(candidate_ids)))
            self.assertTrue(
                all(item.startswith("candidate-") for item in candidate_ids)
            )
            mapped_ids = {
                record["candidate_id"]
                for record in classifications["records"]
                if record["candidate_id"] is not None
            }
            self.assertEqual(set(candidate_ids), mapped_ids)
            self.assertTrue(
                all(
                    record["classification"] in {"candidate", "rejected"}
                    and "qualification" not in record
                    and "verdict" not in record
                    for record in classifications["records"]
                )
            )

    def test_candidate_grouping_is_deterministic_and_bounded(self) -> None:
        cases = {
            "backend/onyx/auth/users.py": "backend/onyx/auth",
            "backend/ee/onyx/auth/users.py": "backend/ee/onyx/auth",
            "web/src/app/admin/page.tsx": "web/src/app/admin",
            "web/src/components/Button.tsx": "web/src/components",
            "deployment/docker_compose/docker-compose.yml": "deployment/docker_compose",
            "README.md": "README.md",
        }
        self.assertEqual(
            {path: _candidate_group(path) for path in cases},
            cases,
        )

    def test_policy_and_committed_output_drift_fail_closed(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="pmorg-candidate-search-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "repo"
        subprocess.run(
            ["git", "clone", "-q", "--shared", str(REPOSITORY_ROOT), str(root)],
            check=True,
        )
        for relative_path in (
            "backend/pmorg/application/candidate_search.py",
            "pmorg/capabilities/candidate-search-policy.json",
            "pmorg/capabilities/candidate-search",
        ):
            source = REPOSITORY_ROOT / relative_path
            target = root / relative_path
            if source.is_dir():
                shutil.copytree(source, target, dirs_exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        check_candidate_search(root)

        output_path = sorted(
            (root / "pmorg/capabilities/candidate-search").glob(
                "*-search-evidence-v1.json"
            )
        )[0]
        output = cast(dict[str, Any], json.loads(output_path.read_bytes()))
        output["scanned_path_count"] -= 1
        output_path.write_text(json.dumps(output, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(CandidateSearchError, "artifact drifted"):
            check_candidate_search(root)

        shutil.copytree(
            SEARCH_ROOT,
            root / "pmorg/capabilities/candidate-search",
            dirs_exist_ok=True,
        )
        policy_path = root / "pmorg/capabilities/candidate-search-policy.json"
        policy = cast(dict[str, Any], json.loads(policy_path.read_bytes()))
        capabilities = cast(list[dict[str, Any]], policy["capabilities"])
        capabilities[0]["minimum_candidate_group_count"] = 1
        policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(CandidateSearchError, "threshold is invalid"):
            derive_candidate_search_outputs(root)


if __name__ == "__main__":
    unittest.main()
