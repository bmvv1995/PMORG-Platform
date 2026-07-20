from __future__ import annotations

import unittest

import pmorg.tests as active_suite
from pmorg.tests import active_suite_plan


class TestActiveSuiteDiscovery(unittest.TestCase):
    def test_retired_protector_set_is_exact(self) -> None:
        plan = active_suite_plan()

        self.assertEqual(
            plan.retired_protectors,
            ("pmorg.tests.test_helm_ci_seam_protector",),
        )

    def test_active_protector_set_is_exact(self) -> None:
        plan = active_suite_plan()

        self.assertEqual(
            set(plan.active_protectors),
            {
                "pmorg.tests.test_actionlint_helm_lane_seam_protector",
                "pmorg.tests.test_helm_static_lane_ci_seam_protector",
                "pmorg.tests.test_zizmor_ci_seam_protector",
            },
        )

    def test_exclusion_loses_no_non_retired_module(self) -> None:
        plan = active_suite_plan()
        retired = set(plan.retired_protectors)
        included = set(plan.included_modules)

        self.assertFalse(retired & included)
        self.assertEqual(included | retired, set(plan.all_modules))
        self.assertIn("pmorg.tests.test_verify_fork", included)
        self.assertIn("pmorg.tests.test_active_suite_discovery", included)

    def test_active_protectors_are_discovered(self) -> None:
        plan = active_suite_plan()

        self.assertLessEqual(
            set(plan.active_protectors),
            set(plan.included_modules),
        )

    def test_collection_errors_are_not_swallowed(self) -> None:
        class RaisingLoader(unittest.TestLoader):
            def loadTestsFromModule(self, module, *, pattern=None):  # noqa: N802
                raise ImportError(f"sentinel import failure: {module.__name__}")

        with self.assertRaisesRegex(ImportError, "sentinel import failure"):
            active_suite.load_tests(
                RaisingLoader(), unittest.TestSuite(), "test_*.py"
            )


if __name__ == "__main__":
    unittest.main()
