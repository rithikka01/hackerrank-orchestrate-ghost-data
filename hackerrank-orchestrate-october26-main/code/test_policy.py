import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import PolicyBook


class PolicyBookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.book = PolicyBook.from_csv(Path(__file__).resolve().parents[1] / "dataset" / "deletion_rules.csv")

    def test_loads_all_fifteen_supplied_rules(self):
        self.assertEqual(len(self.book.rules), 15)

    def test_always_delete_rules_are_applied(self):
        self.assertEqual(self.book.required_action("USER_PROFILE", {}, "2026-01-01T00:00:00Z", linked_to_subject=True, direct_identifier_present=True), "DELETE")
        self.assertEqual(self.book.required_action("USER_EXPORT", {}, "2026-01-01T00:00:00Z", linked_to_subject=True, direct_identifier_present=True), "DELETE")

    def test_shared_support_context_is_redacted(self):
        self.assertEqual(self.book.required_action("SUPPORT_MESSAGE", {"order_id":"ord-1","message_excerpt":"delivery discussion"}, "2026-01-01T00:00:00Z", linked_to_subject=True, direct_identifier_present=True), "REDACT")

    def test_subject_only_support_message_is_deleted(self):
        action = self.book.required_action("SUPPORT_MESSAGE", {"message_text": "private customer note", "subject_only": True},
                                           "2026-01-01T00:00:00Z", linked_to_subject=True,
                                           direct_identifier_present=True)
        self.assertEqual(action, "DELETE")

    def test_support_message_with_unknown_context_is_redacted_conservatively(self):
        action = self.book.required_action("SUPPORT_MESSAGE", {"message_text": "identifiable customer note"},
                                           "2026-01-01T00:00:00Z", linked_to_subject=True,
                                           direct_identifier_present=True)
        self.assertEqual(action, "REDACT")

    def test_expired_security_retention_does_not_require_retention(self):
        action=self.book.required_action("SECURITY_AUDIT_LOG", {"retention_until":"2025-01-01T00:00:00Z"}, "2026-01-01T00:00:00Z", linked_to_subject=True, direct_identifier_present=False)
        self.assertEqual(action, "DELETE")

    def test_backup_is_retained_when_restore_can_be_blocked(self):
        self.assertEqual(self.book.required_action("BACKUP_ARCHIVE", {"restore_blockable":True}, "2026-01-01T00:00:00Z", linked_to_subject=True, direct_identifier_present=False), "RETAIN")


if __name__ == "__main__":
    unittest.main()
