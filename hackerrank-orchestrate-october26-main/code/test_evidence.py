import importlib.util
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import _state
from evidence import EvidenceCatalog, EvidenceRecord, evidence_visible, matches_subject


class EvidenceCatalogTests(unittest.TestCase):
    def test_loads_manifest_and_supported_structured_evidence(self):
        catalog = EvidenceCatalog(Path(__file__).resolve().parents[1] / "dataset").load()
        self.assertEqual(len(catalog.manifest), 94)
        self.assertGreater(len(catalog.records), 1000)
        self.assertTrue(any(record.source_format == "sql" for record in catalog.records))
        self.assertTrue(any(record.source_format == "json" for record in catalog.records))
        self.assertTrue(any(record.source_format == "log" for record in catalog.records))
        self.assertTrue(all(record.file_id in catalog.manifest for record in catalog.records))

    def test_keeps_timestamp_and_provenance_for_each_record(self):
        catalog = EvidenceCatalog(Path(__file__).resolve().parents[1] / "dataset").load()
        self.assertTrue(all(record.captured_at for record in catalog.records))
        self.assertTrue(all(record.file_path.startswith("evidence/") for record in catalog.records))

    def test_records_active_and_blocked_restore_flags_without_deciding_case(self):
        catalog = EvidenceCatalog(Path(__file__).resolve().parents[1] / "dataset").load()
        restore_rows = [r for r in catalog.records if r.category == "BACKUP_ARCHIVE" and "restore_allowed" in r.attributes]
        self.assertTrue(restore_rows)
        self.assertTrue(any(row.attributes["restore_allowed"] is True for row in restore_rows))
        self.assertTrue(any(row.attributes["restore_allowed"] is False for row in restore_rows))

    def test_records_enabled_and_disabled_flow_flags(self):
        catalog = EvidenceCatalog(Path(__file__).resolve().parents[1] / "dataset").load()
        flow_rows = [r for r in catalog.records if r.category == "DATA_FLOW" and "enabled" in r.attributes]
        self.assertTrue(flow_rows)
        self.assertTrue(any(row.attributes["enabled"] is True for row in flow_rows))
        self.assertTrue(any(row.attributes["enabled"] is False for row in flow_rows))

    def test_matches_subject_identifiers_in_document_page_text(self):
        record = EvidenceRecord(
            file_id="evidence_test", file_path="evidence/test.pdf",
            captured_at="2026-01-01T00:00:00Z", source_format="pdf",
            system_id="support_platform", resource_id="support_1",
            category="SUPPORT_MESSAGE", observed_at="2026-01-01T00:00:00Z",
            attributes={"page": 1, "text": "Customer email: person@example.test"},
        )
        self.assertTrue(matches_subject(record, {"email": {"person@example.test"}}))

    def test_evidence_after_audit_cutoff_is_not_visible(self):
        record = EvidenceRecord(
            file_id="evidence_future", file_path="evidence/test.json",
            captured_at="2026-09-16T00:00:00Z", source_format="json",
            system_id="account_service", resource_id="account_1", category="USER_PROFILE",
            observed_at="2026-09-15T11:00:00Z", attributes={"status_code": 404},
        )
        self.assertFalse(evidence_visible(record, "2026-09-15T12:00:00Z"))

    def test_near_match_email_does_not_link_decoy_record(self):
        record = EvidenceRecord(
            file_id="evidence_decoy", file_path="evidence/image.png",
            captured_at="2026-09-01T00:00:00Z", source_format="image",
            system_id="search_service", resource_id="search_2", category="SEARCH_INDEX_ENTRY",
            observed_at="2026-09-01T00:00:00Z", attributes={"text": "g.silva76.jr@gmail.com"},
        )
        self.assertFalse(matches_subject(record, {"email": {"g.silva76@gmail.com"}}))

    def test_maps_export_jobs_collection_to_policy_category(self):
        self.assertEqual(EvidenceCatalog._category("customer_export_jobs", {}), "USER_EXPORT")

    def test_maps_deleted_customer_reference_snapshot_to_tombstone_category(self):
        self.assertEqual(EvidenceCatalog._category("deleted_customer_references", {"account_status": "DELETED"}), "ACCOUNT_TOMBSTONE")

    def test_ambiguous_explicit_categories_fail_closed_deterministically(self):
        for text in ("SEARCH_INDEX_ENTRY DATA_FLOW", "DATA_FLOW SEARCH_INDEX_ENTRY"):
            self.assertEqual(EvidenceCatalog._category(text, {}), "UNKNOWN")

    def test_image_rows_keep_their_own_categories_on_mixed_category_page(self):
        class FakeOCR:
            def __call__(self, _path):
                return ([
                    ([[0, 10], [200, 10], [200, 20], [0, 20]],
                     "SEARCH_INDEX_ENTRY search_100 state=PRESENT", 0.99),
                    ([[0, 100], [200, 100], [200, 110], [0, 110]],
                     "DATA_FLOW data_flow_200 enabled=false", 0.99),
                    ([[0, 190], [200, 190], [200, 200], [0, 200]],
                     "data_flow_300 analytics payload", 0.99),
                ], 0.0)

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as temporary:
            path = Path(temporary) / "mixed_console.png"
            path.write_bytes(b"image stub; OCR is mocked")
            catalog = EvidenceCatalog(Path(temporary))
            meta = {
                "file_id": "evidence_mixed",
                "file_path": "evidence/images/connector_management_console.png",
                "captured_at": "2026-09-10T08:00:00Z",
                "origin": "integration_admin",
            }
            with patch.object(EvidenceCatalog, "_shared_ocr_engine", FakeOCR()):
                catalog._parse_image(meta, path)

        categories = {record.resource_id: record.category for record in catalog.records}
        self.assertEqual(categories, {
            "search_100": "SEARCH_INDEX_ENTRY",
            "data_flow_200": "DATA_FLOW",
            "data_flow_300": "DATA_FLOW",
        })

    def test_maps_deletion_marker_check_to_secondary_identifier(self):
        self.assertEqual(EvidenceCatalog._category("marker_check", {"event": "deletion_marker_check"}), "SECONDARY_IDENTIFIER")

    def test_pdf_filename_identifies_subject_attachment_category(self):
        dataset = Path(__file__).resolve().parents[1] / "dataset"
        path = dataset / "evidence" / "documents" / "delivery_correction_attachment.pdf"
        catalog = EvidenceCatalog(dataset)
        catalog._parse_pdf({
            "file_id": "evidence_attachment_test",
            "file_path": "evidence/documents/delivery_correction_attachment.pdf",
            "captured_at": "2026-09-12T07:30:00Z",
            "origin": "support_platform",
        }, path)
        matching = [record for record in catalog.records if record.resource_id == "support_001"]
        self.assertTrue(matching)
        self.assertTrue(all(record.category == "SUPPORT_ATTACHMENT" for record in matching))

    def test_parses_root_json_records_using_explicit_record_type(self):
        path = Path("resource_export.json")
        payload = ('{"exported_at":"2026-08-12T09:00:00Z","records":['
                   '{"recorded_at":"2026-08-12T09:00:00Z","system":"account_service",'
                   '"resource_id":"account_1084","record_type":"USER_PROFILE",'
                   '"result":"NOT_FOUND","subject_reference":"user@example.test"}]}')
        catalog = EvidenceCatalog(Path("."))
        with patch.object(Path, "read_text", return_value=payload):
            catalog._parse_json({
                "file_id": "evidence_json_records", "file_path": "evidence/records/resource_export.json",
                "captured_at": "2026-08-12T08:55:00Z", "origin": "participant_export",
            }, path)
        self.assertEqual(len(catalog.records), 1)
        record = catalog.records[0]
        self.assertEqual(record.system_id, "account_service")
        self.assertEqual(record.resource_id, "account_1084")
        self.assertEqual(record.category, "USER_PROFILE")
        self.assertEqual(record.observed_at, "2026-08-12T09:00:00Z")
        self.assertTrue(evidence_visible(record, "2026-08-12T09:05:00Z"))
        self.assertFalse(evidence_visible(record, "2026-08-12T08:59:00Z"))
        self.assertEqual(record.attributes["result"], "NOT_FOUND")

    def test_parses_json_formatted_log_fields_and_state(self):
        path = Path("structured.log")
        line = ('2026-09-16T08:52:59Z {"service":"security_service",'
                '"resource_id":"audit_record_4902","event":"audit_record_read_completed",'
                '"rows":"1","trace_id":"trace_4902"}\n')
        catalog = EvidenceCatalog(Path("."))
        with patch.object(Path, "read_text", return_value=line):
            catalog._parse_text({
                "file_id": "evidence_structured", "file_path": "evidence/structured.log",
                "captured_at": "2026-09-18T11:55:24Z", "origin": "central_observability_export",
            }, path)
        self.assertEqual(len(catalog.records), 1)
        record = catalog.records[0]
        self.assertEqual(record.resource_id, "audit_record_4902")
        self.assertEqual(record.system_id, "security_service")
        self.assertEqual(record.attributes["rows"], "1")
        self.assertEqual(record.attributes["trace_id"], "trace_4902")
        self.assertEqual(_state(record), "PRESENT")
        self.assertEqual(len(catalog.trace_events), 1)

    def test_structured_log_observation_is_excluded_when_file_capture_is_after_cutoff(self):
        path = Path("structured.log")
        line = ('2026-09-16T08:57:34Z {"service":"account_service",'
                '"resource_id":"account_9","event":"profile_lookup_completed",'
                '"rows":"0","http_status":"404"}\n')
        catalog = EvidenceCatalog(Path("."))
        with patch.object(Path, "read_text", return_value=line):
            catalog._parse_text({
                "file_id": "evidence_future", "file_path": "evidence/structured.log",
                "captured_at": "2026-09-18T11:55:24Z", "origin": "central_observability_export",
            }, path)
        record = catalog.records[0]
        self.assertEqual(_state(record), "ABSENT")
        self.assertFalse(evidence_visible(record, "2026-09-16T09:00:00Z"))

    def test_parses_escaped_nested_observability_message_fields(self):
        path = Path("runtime.log")
        line = ('2026-06-08T06:52:09Z requestId=trace-1 level=INFO '
                'function=search_service message="instance=\\"search-3\\" '
                'pod=\\"search-0696\\" resource_id=\\"search_021\\" '
                'event=\\"index_query_completed\\" result=\\"hit\\""\n')
        catalog = EvidenceCatalog(Path("."))
        with patch.object(Path, "read_text", return_value=line):
            catalog._parse_text({
                "file_id": "evidence_runtime", "file_path": "evidence/logs/runtime.log",
                "captured_at": "2026-06-08T07:00:00Z", "origin": "central_observability_export",
            }, path)
        self.assertEqual(len(catalog.records), 1)
        record = catalog.records[0]
        self.assertEqual(record.resource_id, "search_021")
        self.assertEqual(record.system_id, "search_service")
        self.assertEqual(record.observed_at, "2026-06-08T06:52:09Z")
        self.assertEqual(record.attributes["result"], "hit")
        self.assertEqual(_state(record), "PRESENT")
        self.assertEqual(record.file_id, "evidence_runtime")

    def test_uses_manifest_origin_when_log_service_is_internal_replica(self):
        path = Path("replica.log")
        line = "2026-09-17T22:00:05Z service=support_replica event=contact_query_completed resource_id=support_002 rows=1\n"
        catalog = EvidenceCatalog(Path("."))
        with patch.object(Path, "read_text", return_value=line):
            catalog._parse_text({"file_id": "evidence_test", "file_path": "evidence/replica.log", "captured_at": "2026-09-17T22:01:00Z", "origin": "support_platform"}, path)
        self.assertEqual(len(catalog.records), 1)
        self.assertEqual(catalog.records[0].system_id, "support_platform")

    @unittest.skipUnless(importlib.util.find_spec("rapidocr_onnxruntime"), "OCR dependency is optional")
    def test_ocr_preserves_manifest_provenance_and_subject_text(self):
        catalog = EvidenceCatalog(Path(__file__).resolve().parents[1] / "dataset").load()
        records = [r for r in catalog.records if r.file_id == "evidence_14" and r.resource_id == "data_flow_9846"]
        self.assertTrue(records)
        self.assertTrue(any("lucia-torres@gmail.com" in r.attributes["text"].casefold() for r in records))
        self.assertEqual(records[0].source_format, "image")
        self.assertEqual(records[0].file_id, catalog.manifest["evidence_14"]["file_id"])
        decoy = [r for r in catalog.records if r.file_id == "evidence_14" and r.resource_id == "data_flow_1121"]
        self.assertTrue(decoy)
        self.assertFalse(any(matches_subject(r, {"email": {"lucia-torres@gmail.com"}}) for r in decoy))
        self.assertFalse(any(r.file_id == "evidence_14" and r.resource_id == "analytics_warehouse"
                             for r in catalog.records))

    def test_does_not_treat_log_service_name_as_resource_id(self):
        catalog = EvidenceCatalog(Path(__file__).resolve().parents[1] / "dataset").load()
        fake = [r for r in catalog.records if r.file_id == "evidence_61" and r.resource_id == "support_replica"]
        self.assertEqual(fake, [])


if __name__ == "__main__":
    unittest.main()
