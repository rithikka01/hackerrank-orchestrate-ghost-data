import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from intent import RequestIntent, classify_request


class IntentTests(unittest.TestCase):
    def test_clear_english_deletion(self):
        self.assertEqual(classify_request("Please erase my account and personal data."), RequestIntent.DELETION)

    def test_deletion_gerund_and_existing_deletion_audit_language(self):
        self.assertEqual(classify_request("I am deleting my account."), RequestIntent.DELETION)
        self.assertEqual(classify_request("Check whether the profile has already been removed."), RequestIntent.DELETION)
        self.assertEqual(classify_request("Please remove the old search result."), RequestIntent.DELETION)

    def test_profile_gone_is_deletion_audit_intent(self):
        self.assertEqual(classify_request("Confirm the profile is gone and cannot identify me."), RequestIntent.DELETION)

    def test_clear_spanish_deletion(self):
        self.assertEqual(classify_request("Quiero eliminar mi cuenta."), RequestIntent.DELETION)

    def test_clear_french_deletion(self):
        self.assertEqual(classify_request("Je demande la suppression du compte."), RequestIntent.DELETION)

    def test_clear_japanese_and_korean_deletion(self):
        self.assertEqual(classify_request("アカウントを削除してください"), RequestIntent.DELETION)
        self.assertEqual(classify_request("계정을 삭제해 주세요"), RequestIntent.DELETION)

    def test_access_and_marketing_requests_are_not_deletion(self):
        self.assertEqual(classify_request("Please export a copy of my data."), RequestIntent.NOT_DELETION)
        self.assertEqual(classify_request("Stop marketing emails and unsubscribe me."), RequestIntent.NOT_DELETION)

    def test_explicit_negative_does_not_authorize_deletion(self):
        self.assertEqual(classify_request("Do not delete my account; only update my email."), RequestIntent.NOT_DELETION)

    def test_unrecognized_text_is_uncertain(self):
        self.assertEqual(classify_request("I have a question about my account."), RequestIntent.UNCERTAIN)


if __name__ == "__main__":
    unittest.main()
