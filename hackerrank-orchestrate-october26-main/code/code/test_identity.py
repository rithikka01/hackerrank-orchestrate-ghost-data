import unittest

from identity import IdentityIndex, normalize_identifier


class IdentityIndexTests(unittest.TestCase):
    def test_resolves_current_email_case_insensitively(self):
        index = IdentityIndex(
            [{"user_id": "u1", "email": "Current@Example.test", "updated_at": "2026-01-01T00:00:00Z"}],
            [],
        )
        self.assertEqual(index.resolve_email(" current@example.test ", "2026-02-01T00:00:00Z"), "u1")

    def test_resolves_historical_email_and_returns_aliases(self):
        index = IdentityIndex(
            [{"user_id": "u1", "email": "new@example.test", "updated_at": "2026-02-01T00:00:00Z"}],
            [{"user_id": "u1", "field_name": "email", "old_value": "old@example.test", "new_value": "new@example.test", "event_time": "2026-01-15T00:00:00Z"}],
        )
        cutoff = "2026-03-01T00:00:00Z"
        self.assertEqual(index.resolve_email("OLD@example.test", cutoff), "u1")
        self.assertEqual(index.identifiers_for("u1", cutoff)["email"], {"old@example.test", "new@example.test"})

    def test_excludes_future_identity_and_audit_events(self):
        index = IdentityIndex(
            [{"user_id": "u1", "email": "future@example.test", "updated_at": "2026-03-01T00:00:00Z"}],
            [{"user_id": "u1", "field_name": "email", "old_value": "prior@example.test", "new_value": "future@example.test", "event_time": "2026-03-01T00:00:00Z"}],
        )
        cutoff = "2026-02-01T00:00:00Z"
        self.assertIsNone(index.resolve_email("future@example.test", cutoff))
        self.assertEqual(index.identifiers_for("u1", cutoff)["email"], set())

    def test_ambiguous_email_fails_closed(self):
        index = IdentityIndex(
            [
                {"user_id": "u1", "email": "shared@example.test", "updated_at": "2026-01-01T00:00:00Z"},
                {"user_id": "u2", "email": "SHARED@example.test", "updated_at": "2026-01-01T00:00:00Z"},
            ],
            [],
        )
        self.assertIsNone(index.resolve_email("shared@example.test", "2026-02-01T00:00:00Z"))

    def test_phone_formatting_is_normalized_for_matching(self):
        self.assertEqual(normalize_identifier("phone", "+1 (202) 555-0100"), "12025550100")

    def test_invalid_cutoff_fails_closed(self):
        index = IdentityIndex(
            [{"user_id": "u1", "email": "a@example.test", "updated_at": "2026-01-01T00:00:00Z"}],
            [],
        )
        self.assertIsNone(index.resolve_email("a@example.test", "not-a-time"))


if __name__ == "__main__":
    unittest.main()
