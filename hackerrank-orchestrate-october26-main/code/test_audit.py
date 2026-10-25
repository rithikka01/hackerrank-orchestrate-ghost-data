import sys
import unittest
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import AuditEngine, _state
from evidence import EvidenceRecord
from identity import IdentityIndex
from policy import PolicyBook


class AuditStateTests(unittest.TestCase):
    @staticmethod
    def _link_engine(records):
        engine = object.__new__(AuditEngine)
        engine.catalog = SimpleNamespace(records=records, trace_events=[])
        engine.activities = []
        return engine

    def test_follows_explicit_source_resource_reference(self):
        root = EvidenceRecord(
            "evidence_root", "evidence/root.sql", "2026-09-10T08:45:00Z", "sql",
            "search_service", "search_001", "SEARCH_INDEX_ENTRY", "2026-09-09T22:12:00Z",
            {"email": "person@example.test", "source_resource_id": "account_006"},
        )
        target = EvidenceRecord(
            "evidence_target", "evidence/accounts.sql", "2026-09-02T23:00:00Z", "sql",
            "account_service", "account_006", "USER_PROFILE", "2026-09-02T22:45:00Z",
            {"status_code": 404},
        )
        engine = self._link_engine([root, target])
        linked = engine._resource_links({"email": {"person@example.test"}}, "2026-09-10T09:15:00Z")
        self.assertEqual(linked, {"search_001", "account_006"})
        linked_records = engine._latest_subject_records(linked, "2026-09-10T09:15:00Z")
        account = next(record for record in linked_records if record.resource_id == "account_006")
        self.assertEqual(account.file_id, "evidence_target")
        self.assertEqual(account.system_id, "account_service")
        self.assertEqual(_state(account), "ABSENT")

    def test_missing_typed_reference_target_is_retained_without_claiming_state(self):
        root = EvidenceRecord(
            "evidence_root", "evidence/root.json", "2026-09-10T08:00:00Z", "json",
            "search_service", "search_1", "SEARCH_INDEX_ENTRY", "2026-09-10T08:00:00Z",
            {"email": "person@example.test", "related_resource_id": "account_missing"},
        )
        engine = self._link_engine([root])
        linked = engine._resource_links({"email": {"person@example.test"}}, "2026-09-10T09:00:00Z")
        self.assertIn("account_missing", linked)
        self.assertEqual(engine._latest_subject_records(linked, "2026-09-10T09:00:00Z"), [root])

    def test_ambiguous_reference_targets_are_not_traversed(self):
        root = EvidenceRecord(
            "evidence_root", "evidence/root.json", "2026-09-10T08:00:00Z", "json",
            "search_service", "search_1", "SEARCH_INDEX_ENTRY", "2026-09-10T08:00:00Z",
            {"email": "person@example.test", "related_resource_id": "data_flow_9"},
        )
        left = EvidenceRecord("evidence_a", "a.json", "2026-09-10T08:00:00Z", "json", "integration_service", "data_flow_9", "DATA_FLOW", "2026-09-10T08:00:00Z", {})
        right = EvidenceRecord("evidence_b", "b.json", "2026-09-10T08:00:00Z", "json", "search_service", "data_flow_9", "SEARCH_INDEX_ENTRY", "2026-09-10T08:00:00Z", {})
        linked = self._link_engine([root, left, right])._resource_links(
            {"email": {"person@example.test"}}, "2026-09-10T09:00:00Z")
        self.assertEqual(linked, {"search_1"})

    def test_resource_reference_cycles_terminate_and_preserve_both_links(self):
        root = EvidenceRecord(
            "evidence_a", "a.json", "2026-09-10T08:00:00Z", "json", "search_service",
            "search_1", "SEARCH_INDEX_ENTRY", "2026-09-10T08:00:00Z",
            {"email": "person@example.test", "related_resource_id": "data_flow_2"},
        )
        child = EvidenceRecord(
            "evidence_b", "b.json", "2026-09-10T08:00:00Z", "json", "integration_service",
            "data_flow_2", "DATA_FLOW", "2026-09-10T08:00:00Z",
            {"related_resource_id": "search_1"},
        )
        linked = self._link_engine([root, child])._resource_links(
            {"email": {"person@example.test"}}, "2026-09-10T09:00:00Z")
        self.assertEqual(linked, {"search_1", "data_flow_2"})

    def test_post_cutoff_reference_target_cannot_supply_state(self):
        root = EvidenceRecord(
            "evidence_root", "evidence/root.json", "2026-09-10T08:00:00Z", "json",
            "search_service", "search_1", "SEARCH_INDEX_ENTRY", "2026-09-10T08:00:00Z",
            {"email": "person@example.test", "source_resource_id": "account_9"},
        )
        future = EvidenceRecord(
            "evidence_future", "evidence/future.json", "2026-09-18T11:55:24Z", "json",
            "account_service", "account_9", "USER_PROFILE", "2026-09-16T08:57:34Z",
            {"status_code": 404},
        )
        engine = self._link_engine([root, future])
        linked = engine._resource_links({"email": {"person@example.test"}}, "2026-09-16T09:00:00Z")
        self.assertEqual(linked, {"search_1", "account_9"})
        self.assertEqual(engine._latest_subject_records(linked, "2026-09-16T09:00:00Z"), [root])

    def test_successful_activity_claim_does_not_prove_resource_absence(self):
        record = EvidenceRecord(
            file_id="activity_1", file_path="system_activity.csv",
            captured_at="2026-09-01T00:00:00Z", source_format="activity",
            system_id="account_service", resource_id="account_1", category="USER_PROFILE",
            observed_at="2026-09-01T00:00:00Z",
            attributes={"event_type": "DELETE_RECORD", "reported_result": "SUCCESS"},
            evidence_kind="activity_claim",
        )
        self.assertEqual(_state(record), "UNKNOWN")


    def test_residual_record_proves_incomplete_without_inventing_account_resource(self):
        record = EvidenceRecord(
            "evidence_test", "evidence/test.json", "2026-09-01T00:00:00Z", "json",
            "search_service", "search_test", "SEARCH_INDEX_ENTRY", "2026-09-01T00:00:00Z",
            {"email": "person@example.test"}, "snapshot",
        )
        engine = object.__new__(AuditEngine)
        engine.identities = IdentityIndex([{
            "user_id": "user_test", "email": "person@example.test",
            "updated_at": "2026-09-01T00:00:00Z",
        }], [])
        engine.catalog = SimpleNamespace(records=[record], scopes=[], trace_events=[], manifest={})
        engine.activities = []
        engine.rules = PolicyBook.from_csv(Path(__file__).resolve().parents[1] / "dataset" / "deletion_rules.csv")
        request = {
            "case_id": "synthetic_case", "email": "person@example.test",
            "audit_at": "2026-09-02T00:00:00Z",
            "request_text": "Please delete my account and personal data.",
        }
        result = engine.audit_one(request)
        self.assertEqual(result["deletion_status"], "INCOMPLETE")
        self.assertTrue(any(step["resource_id"] == "search_test" for step in result["steps"]))
        self.assertFalse(any(step["system_id"] == "account_service" for step in result["steps"]))

    def test_restore_candidate_without_deletion_block_is_active_risk(self):
        record = EvidenceRecord(
            "evidence_1", "evidence/restore.log", "2026-09-01T00:00:00Z", "log",
            "backup_service", "backup_1", "BACKUP_ARCHIVE", "2026-09-01T00:00:00Z",
            {"eligible": "true", "deletion_block": "false"}, "log_claim",
        )
        self.assertEqual(_state(record), "ACTIVE")


if __name__ == "__main__":
    unittest.main()
