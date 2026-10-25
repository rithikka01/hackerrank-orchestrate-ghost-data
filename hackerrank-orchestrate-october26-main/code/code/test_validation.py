import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validation import validate_predictions


class OutputValidationTests(unittest.TestCase):
    def test_rejects_complete_status_with_finding_or_missing_citation(self):
        predictions = [{"case_id": "case_1", "deletion_status": "COMPLETE", "steps": [{
            "step_no": 1, "phase": "FINDING", "system_id": "account_service",
            "resource_id": "account_1", "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT", "evidence_id": "",
        }]}]
        errors = validate_predictions(predictions, [{"case_id": "case_1"}], set())
        self.assertTrue(any("COMPLETE may contain only verification" in error for error in errors))
        self.assertTrue(any("finding step" in error for error in errors))

    def test_accepts_sorted_not_applicable_empty_array(self):
        predictions = [{"case_id": "case_1", "deletion_status": "NOT_APPLICABLE", "steps": []}]
        self.assertEqual(validate_predictions(predictions, [{"case_id": "case_1"}], set()), [])

    def test_rejects_incomplete_plan_with_future_evidence_reference(self):
        steps = [
            {"step_no": 1, "phase": "FINDING", "system_id": "account_service", "resource_id": "account_1", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_1"},
            {"step_no": 2, "phase": "REMEDIATION", "system_id": "account_service", "resource_id": "account_1", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
            {"step_no": 3, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_1", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_1"},
        ]
        errors = validate_predictions([{"case_id": "case_1", "deletion_status": "INCOMPLETE", "steps": steps}], [{"case_id": "case_1"}], {"evidence_1"})
        self.assertTrue(any("evidence_id must be empty" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
