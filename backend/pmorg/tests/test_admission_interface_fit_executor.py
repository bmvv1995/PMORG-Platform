from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any

from pmorg.application.admission_interface_fit_executor import (
    AdmissionInterfaceFitError,
)
from pmorg.application.admission_interface_fit_executor import (
    execute_admission_interface_fit,
)
from pmorg.application.qualification_oracles import QualificationOracleError
from pmorg.application.qualification_oracles import result_schema
from pmorg.application.qualification_oracles import validate_qualification_oracle_result

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class AdmissionInterfaceFitExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        bundle = json.loads(
            (
                REPOSITORY_ROOT / "pmorg/capabilities/candidate-inputs-v1.json"
            ).read_bytes()
        )
        cls.candidate_ids = {
            capability_id: next(
                item["candidate_id"]
                for item in bundle["candidates"]
                if item["capability_id"] == capability_id
            )
            for capability_id in (
                "deployment-admission",
                "distribution-admission",
            )
        }

    def _execute(self, capability_id: str) -> dict[str, Any]:
        return execute_admission_interface_fit(
            capability_id,
            self.candidate_ids[capability_id],
            repository_root=REPOSITORY_ROOT,
        )

    def test_both_admission_oracles_execute_candidate_bytes(self) -> None:
        for capability_id in self.candidate_ids:
            with self.subTest(capability_id=capability_id):
                result = self._execute(capability_id)
                self.assertEqual(result["oracle_status"], "executable")
                self.assertEqual(result["verdict"], "fail")
                self.assertFalse(result["baseline_fit"])
                self.assertTrue(result["positive_injection_fit"])
                self.assertEqual(
                    result["projected_blob_count"], result["observed_blob_count"]
                )
                self.assertEqual(result["unobserved_blob_count"], 0)
                self.assertNotEqual(
                    result["baseline_observation_digest"],
                    result["mutation_observation_digest"],
                )
                self.assertNotEqual(
                    result["baseline_observation_digest"],
                    result["positive_injection_observation_digest"],
                )
                self.assertEqual(result["execution_exit_codes"], [0, 0, 0])
                validate_qualification_oracle_result(
                    result, repository_root=REPOSITORY_ROOT
                )

    def test_runtime_identity_measures_executed_binary_and_exact_locks(self) -> None:
        result = self._execute("deployment-admission")
        measurement = result["runtime_measurement"]
        assert isinstance(measurement, dict)
        interpreter = Path(sys.executable).resolve().read_bytes()
        self.assertEqual(
            measurement["interpreter_binary"]["digest"],
            "sha256:" + hashlib.sha256(interpreter).hexdigest(),
        )
        self.assertEqual(
            [item["relative_path"] for item in measurement["declared_artifacts"]],
            [".python-version", "pyproject.toml", "uv.lock"],
        )

    def test_mutation_positive_control_and_runtime_tamper_fail_closed(self) -> None:
        result = self._execute("distribution-admission")

        no_influence = copy.deepcopy(result)
        no_influence["mutation_observation_digest"] = no_influence[
            "baseline_observation_digest"
        ]
        with self.assertRaisesRegex(QualificationOracleError, "not evidence-complete"):
            validate_qualification_oracle_result(
                no_influence, repository_root=REPOSITORY_ROOT
            )

        no_positive_control = copy.deepcopy(result)
        no_positive_control["positive_injection_fit"] = False
        with self.assertRaisesRegex(QualificationOracleError, "not evidence-complete"):
            validate_qualification_oracle_result(
                no_positive_control, repository_root=REPOSITORY_ROOT
            )

        runtime_drift = copy.deepcopy(result)
        runtime_drift["runtime_measurement"]["declared_artifacts"][0]["digest"] = (
            "sha256:" + "0" * 64
        )
        with self.assertRaisesRegex(
            QualificationOracleError, "runtime declaration or lock binding drifted"
        ):
            validate_qualification_oracle_result(
                runtime_drift, repository_root=REPOSITORY_ROOT
            )

    def test_result_schema_is_v2_and_unknown_capability_fails(self) -> None:
        self.assertEqual(
            result_schema()["properties"]["schema_version"]["const"],
            "pmorg.qualification-oracle-result/v2",
        )
        with self.assertRaisesRegex(
            AdmissionInterfaceFitError, "unsupported admission capability"
        ):
            execute_admission_interface_fit(
                "unknown",
                "candidate-" + "0" * 64,
                repository_root=REPOSITORY_ROOT,
            )


if __name__ == "__main__":
    unittest.main()
