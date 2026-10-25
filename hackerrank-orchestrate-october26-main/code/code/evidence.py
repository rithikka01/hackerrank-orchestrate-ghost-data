from __future__ import annotations

import csv
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


CATEGORY_BY_NAME = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "analytics_profiles": "ANALYTICS_PROFILE",
    "product_telemetry": "PRODUCT_TELEMETRY",
    "telemetry_events": "PRODUCT_TELEMETRY",
    "support_conversations": "SUPPORT_MESSAGE",
    "support_records": "SUPPORT_MESSAGE",
    "support_messages": "SUPPORT_MESSAGE",
    "support_attachments": "SUPPORT_ATTACHMENT",
    "customer_exports": "USER_EXPORT",
    "user_exports": "USER_EXPORT",
    "marketing_profiles": "MARKETING_PROFILE",
    "email_delivery_logs": "EMAIL_DELIVERY_LOG",
    "email_delivery_events": "EMAIL_DELIVERY_LOG",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "backup_catalog": "BACKUP_ARCHIVE",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "connector_configurations": "DATA_FLOW",
    "connector_subscriptions": "DATA_FLOW",
    "account_tombstones": "ACCOUNT_TOMBSTONE",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "tombstones": "ACCOUNT_TOMBSTONE",
    "cache_entries": "CACHE_ENTRY",
    "secondary_identifiers": "SECONDARY_IDENTIFIER",
    "profiles": "ANALYTICS_PROFILE",
    "tickets": "SUPPORT_MESSAGE",
    "connectors": "DATA_FLOW",
    "restore_entries": "BACKUP_ARCHIVE",
    "exports": "USER_EXPORT",
    "customer_export_jobs": "USER_EXPORT",
    "audit_records": "SECURITY_AUDIT_LOG",
    "profile_lookups": "USER_PROFILE",
    "user_profile": "USER_PROFILE",
    "secondary_identifier": "SECONDARY_IDENTIFIER",
    "search_index_entry": "SEARCH_INDEX_ENTRY",
    "cache_entry": "CACHE_ENTRY",
    "support_message": "SUPPORT_MESSAGE",
    "support_attachment": "SUPPORT_ATTACHMENT",
    "analytics_profile": "ANALYTICS_PROFILE",
    "product_telemetry": "PRODUCT_TELEMETRY",
    "user_export": "USER_EXPORT",
    "marketing_profile": "MARKETING_PROFILE",
    "email_delivery_log": "EMAIL_DELIVERY_LOG",
    "security_audit_log": "SECURITY_AUDIT_LOG",
    "legal_hold_record": "LEGAL_HOLD_RECORD",
    "backup_archive": "BACKUP_ARCHIVE",
    "account_tombstone": "ACCOUNT_TOMBSTONE",
}

SYSTEM_BY_GROUP = {
    "account_service": "account_service",
    "analytics_platform": "analytics_platform",
    "backup_service": "backup_service",
    "export_service": "export_service",
    "integration_service": "integration_service",
    "search_service": "search_service",
    "security_service": "security_service",
    "support_platform": "support_platform",
    "marketing_platform": "marketing_platform",
    "email_delivery_service": "email_delivery_service",
}

RESOURCE_PATTERN = re.compile(r"(?<![A-Za-z])(?:account|analytics|backup|data_flow|email_delivery|export|search|support|audit_record|tombstone|cache|secondary_identifier|telemetry|attachment|invoice|order)_[A-Za-z0-9-]+\b", re.I)
KEY_VALUE_PATTERN = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.-]*)=(?:\"((?:\\.|[^\"\\])*)\"|"
    r"'((?:\\.|[^'\\])*)'|([^\s]+))"
)


@dataclass(frozen=True)
class EvidenceRecord:
    file_id: str
    file_path: str
    captured_at: str
    source_format: str
    system_id: str
    resource_id: str
    category: str
    observed_at: str
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence_kind: str = "snapshot"


class EvidenceCatalog:
    """Parse participant-facing evidence while retaining provenance and time."""

    _shared_ocr_engine: Any | None = None
    _image_text_cache: dict[tuple[str, int], str] = {}

    def __init__(self, dataset_dir: str | Path):
        self.dataset_dir = Path(dataset_dir).resolve()
        self.manifest: dict[str, dict[str, str]] = {}
        self.records: list[EvidenceRecord] = []
        self.unparsed_images: list[str] = []
        self.scopes: list[dict[str, Any]] = []
        self.trace_events: list[EvidenceRecord] = []
        self._ocr_engine: Any | None = None

    def load(self) -> "EvidenceCatalog":
        manifest_path = self.dataset_dir / "evidence_files.csv"
        with manifest_path.open(encoding="utf-8-sig", newline="") as stream:
            entries = csv.DictReader(stream)
            for row in entries:
                file_id = row.get("file_id", "").strip()
                rel = row.get("file_path", "").strip()
                if not file_id or not rel:
                    continue
                path = (self.dataset_dir / rel).resolve()
                if self.dataset_dir not in path.parents:
                    raise ValueError(f"Evidence path escapes dataset: {rel}")
                meta = {**row, "_absolute_path": str(path)}
                self.manifest[file_id] = meta
                if not path.is_file():
                    continue
                suffix = path.suffix.casefold()
                if suffix == ".json":
                    self._parse_json(meta, path)
                elif suffix == ".sql":
                    self._parse_sql(meta, path)
                elif suffix in {".log", ".txt"}:
                    self._parse_text(meta, path)
                elif suffix == ".pdf":
                    self._parse_pdf(meta, path)
                elif suffix in {".png", ".jpg", ".jpeg"}:
                    self._parse_image(meta, path)
        return self

    def add(self, meta: dict[str, str], source_format: str, system_id: str,
            resource_id: str, category: str, observed_at: str,
            attributes: dict[str, Any], evidence_kind: str = "snapshot") -> None:
        if not resource_id:
            return
        self.records.append(EvidenceRecord(
            file_id=meta["file_id"],
            file_path=meta["file_path"],
            captured_at=meta.get("captured_at", ""),
            source_format=source_format,
            system_id=system_id,
            resource_id=str(resource_id),
            category=category,
            observed_at=str(observed_at or meta.get("captured_at", "")),
            attributes=attributes,
            evidence_kind=evidence_kind,
        ))

    @staticmethod
    def _category(name: str, record: dict[str, Any]) -> str:
        # Some participant JSON exports label each row with `record_type` while
        # the enclosing collection is only the generic word "records".
        # Honor it only when it exactly names a supported policy category.
        record_type = str(record.get("record_type", "")).strip().casefold()
        normalized_type = record_type.replace("-", "_").replace(" ", "_")
        typed_category = CATEGORY_BY_NAME.get(record_type, CATEGORY_BY_NAME.get(normalized_type))
        if typed_category:
            return typed_category
        explicit = record.get("data_category") or record.get("category") or record.get("collection_name") or name
        key = str(explicit).strip().casefold()
        normalized = key.replace("-", "_").replace(" ", "_")
        direct = CATEGORY_BY_NAME.get(key, CATEGORY_BY_NAME.get(normalized))
        if direct:
            return direct
        event = str(record.get("event_type") or record.get("event") or "").casefold()
        searchable = " ".join((str(explicit), str(name), event)).casefold()
        if ("contact_query" in event or "contact_lookup" in event
                or event == "deletion_marker_check"
                or "legacy_contact_index" in searchable):
            return "SECONDARY_IDENTIFIER"
        for category in set(CATEGORY_BY_NAME.values()):
            if re.search(rf"(?<![a-z0-9]){re.escape(category.casefold())}(?![a-z0-9])", searchable):
                return category
        keyword_map = (
            (("profile_lookup", "customer_profile", "account_profile"), "USER_PROFILE"),
            (("search", "index_query", "index_record"), "SEARCH_INDEX_ENTRY"),
            (("analytics",), "ANALYTICS_PROFILE"),
            (("telemetry",), "PRODUCT_TELEMETRY"),
            (("attachment",), "SUPPORT_ATTACHMENT"),
            (("support", "ticket", "conversation"), "SUPPORT_MESSAGE"),
            (("email_delivery", "delivery_log"), "EMAIL_DELIVERY_LOG"),
            (("security_audit", "audit_record"), "SECURITY_AUDIT_LOG"),
            (("legal_hold",), "LEGAL_HOLD_RECORD"),
            (("backup", "restore"), "BACKUP_ARCHIVE"),
            (("tombstone",), "ACCOUNT_TOMBSTONE"),
            (("cache",), "CACHE_ENTRY"),
            (("export",), "USER_EXPORT"),
            (("marketing",), "MARKETING_PROFILE"),
            (("connector", "data_flow", "sync", "import"), "DATA_FLOW"),
            (("secondary_identifier",), "SECONDARY_IDENTIFIER"),
        )
        for needles, category in keyword_map:
            if any(term in searchable for term in needles):
                return category
        return "UNKNOWN"

    @staticmethod
    def _resource(record: dict[str, Any]) -> str:
        for key in ("resource_id", "record_id", "object_id", "id"):
            value = record.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
        return ""

    @staticmethod
    def _system(record: dict[str, Any], fallback: str = "") -> str:
        for key in ("system_id", "origin_system", "data_store", "source_system", "system"):
            value = record.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
        return fallback

    @staticmethod
    def _time(record: dict[str, Any], fallback: str) -> str:
        for key in ("observed_at", "recorded_at", "captured_at", "updated_at", "event_time", "event_at", "timestamp"):
            value = record.get(key)
            if value:
                return str(value)
        return fallback

    def _parse_json(self, meta: dict[str, str], path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return
        fallback = meta.get("captured_at", "")
        if isinstance(data, dict) and isinstance(data.get("snapshots"), list):
            for snapshot in data["snapshots"]:
                if not isinstance(snapshot, dict):
                    continue
                system = str(snapshot.get("data_store", ""))
                collection = str(snapshot.get("collection", ""))
                for record in snapshot.get("records", []) if isinstance(snapshot.get("records"), list) else []:
                    if isinstance(record, dict):
                        self.add(meta, "json", self._system(record, system), self._resource(record), self._category(collection, record), self._time(record, snapshot.get("captured_at", fallback)), record)
        root_records = data.get("records") if isinstance(data, dict) else None
        root_collection = str(data.get("collection", "")) if isinstance(data, dict) else ""
        has_root_records = isinstance(root_records, list) and bool(root_collection)
        if has_root_records and not data.get("snapshots"):
            system = SYSTEM_BY_GROUP.get(root_collection, "")
            for record in root_records:
                if not isinstance(record, dict):
                    continue
                category = self._category(root_collection, record)
                self.add(meta, "json", self._system(record, system), self._resource(record),
                         category, self._time(record, fallback), record)
        exports = data.get("service_exports") if isinstance(data, dict) else None
        if isinstance(exports, dict):
            for service, groups in exports.items():
                if not isinstance(groups, dict):
                    continue
                system = SYSTEM_BY_GROUP.get(service, service)
                for group, records in groups.items():
                    if not isinstance(records, list):
                        continue
                    for record in records:
                        if not isinstance(record, dict):
                            continue
                        if group == "index_queries":
                            query_id = self._resource(record)
                            self.add(meta, "json", system, query_id, "SEARCH_INDEX_ENTRY", self._time(record, fallback), record, "query")
                            hits = record.get("hits")
                            if isinstance(hits, list):
                                for hit in hits:
                                    if isinstance(hit, dict):
                                        self.add(meta, "json", system, self._resource(hit), "SEARCH_INDEX_ENTRY", self._time(hit, self._time(record, fallback)), hit, "record")
                        else:
                            category = self._category(group, record)
                            if group == "profile_lookups":
                                category = "USER_PROFILE"
                            elif group == "profiles":
                                category = "ANALYTICS_PROFILE"
                            elif category == "UNKNOWN":
                                category = self._category(service, record)
                            self.add(meta, "json", system, self._resource(record), category, self._time(record, fallback), record)
        if not isinstance(data, dict) or not (data.get("snapshots") or exports or has_root_records):
            self._walk_json(meta, data, fallback)

    def _walk_json(self, meta: dict[str, str], value: Any, fallback: str, context: str = "") -> None:
        if isinstance(value, dict):
            if self._resource(value):
                self.add(meta, "json", self._system(value), self._resource(value), self._category(context, value), self._time(value, fallback), value)
            for key, nested in value.items():
                if isinstance(nested, (dict, list)):
                    self._walk_json(meta, nested, fallback, str(key))
        elif isinstance(value, list):
            for nested in value:
                self._walk_json(meta, nested, fallback, context)

    def _parse_sql(self, meta: dict[str, str], path: Path) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            source_text = path.read_text(encoding="utf-8-sig")
            complete_snapshot = "point-in-time database snapshot" in source_text[:1200].casefold()
            connection.executescript(source_text)
            names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            complete_snapshot = complete_snapshot or "snapshot_scope" in names
            scopes: dict[str, str] = {}
            if "snapshot_scope" in names:
                columns = [c[1] for c in connection.execute('PRAGMA table_info("snapshot_scope")')]
                for row in connection.execute('SELECT * FROM "snapshot_scope"'):
                    item = dict(zip(columns, row))
                    scopes[str(item.get("origin_system", ""))] = str(item.get("captured_at", meta.get("captured_at", "")))
            for table in names:
                if table == "snapshot_scope":
                    continue
                table_system = table_to_system(table)
                table_capture = scopes.get(table_system, meta.get("captured_at", ""))
                table_category = self._category(table, {})
                self.scopes.append({
                    "file_id": meta["file_id"], "file_path": meta["file_path"], "table": table,
                    "system_id": table_system, "category": table_category,
                    "captured_at": meta.get("captured_at", ""), "observed_at": table_capture,
                    "complete": complete_snapshot,
                })
                columns = [c[1] for c in connection.execute(f'PRAGMA table_info("{table}")')]
                for values in connection.execute(f'SELECT * FROM "{table}"'):
                    row = dict(zip(columns, values))
                    if isinstance(row.get("record_json"), str):
                        try:
                            payload = json.loads(row["record_json"])
                        except json.JSONDecodeError:
                            payload = {}
                    else:
                        payload = {}
                    attributes = {**row, **payload, "snapshot_table": table}
                    system = self._system(attributes) or table_to_system(table)
                    category = self._category(str(attributes.get("collection_name", table)), attributes)
                    observed = self._time(attributes, scopes.get(system, meta.get("captured_at", "")))
                    self.add(meta, "sql", system, self._resource(attributes), category, observed, attributes)
        except (sqlite3.Error, OSError, ValueError):
            return
        finally:
            connection.close()

    def _parse_text(self, meta: dict[str, str], path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            values: dict[str, Any] = {}
            timestamp_match = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?)", line)
            remainder = line[timestamp_match.end():].strip() if timestamp_match else line.strip()
            if remainder.startswith("{"):
                try:
                    structured = json.loads(remainder)
                except json.JSONDecodeError:
                    structured = None
                if isinstance(structured, dict):
                    values.update(structured)
            if not values:
                for match in KEY_VALUE_PATTERN.finditer(line):
                    key = match.group(1)
                    raw = next((g for g in match.groups()[1:] if g is not None), "")
                    value = raw
                    if key == "message" and raw:
                        # Some observability exports put a second key/value log
                        # line inside an escaped JSON-style message string.
                        # Decode that one field, then retain its explicit fields
                        # alongside the outer request metadata.
                        try:
                            decoded = json.loads('"' + raw + '"')
                        except json.JSONDecodeError:
                            decoded = raw
                        nested = list(KEY_VALUE_PATTERN.finditer(decoded))
                        if nested:
                            for nested_match in nested:
                                nested_key = nested_match.group(1)
                                nested_value = next(
                                    (g for g in nested_match.groups()[1:] if g is not None), ""
                                )
                                values[nested_key] = nested_value
                            value = decoded
                    values[key] = value
            pipe_fields = [part.strip() for part in line.split("|")]
            if len(pipe_fields) >= 5 and self._category(pipe_fields[3], {}) != "UNKNOWN":
                values.setdefault("system_id", pipe_fields[1])
                values.setdefault("resource_id", pipe_fields[2])
                values.setdefault("data_category", pipe_fields[3])
                values.setdefault("state", pipe_fields[4])
                if len(pipe_fields) > 5:
                    values.setdefault("subject_identifier", " | ".join(pipe_fields[5:]))
            resources = [
                match.group(0) for match in RESOURCE_PATTERN.finditer(line)
                if any(char.isdigit() for char in match.group(0).rsplit("_", 1)[-1])
            ]
            resource = values.get("resource_id") or (resources[0] if resources else "")
            time_value = timestamp_match.group(1) if timestamp_match else meta.get("captured_at", "")
            system = (values.get("service") or values.get("system_id")
                      or values.get("source_system") or values.get("function") or "")
            known_systems = set(SYSTEM_BY_GROUP.values())
            if system not in known_systems and meta.get("origin") in known_systems:
                # Some logs label an internal worker/replica as `service`; the
                # evidence manifest identifies the originating customer system.
                system = meta["origin"]
            category = self._category(str(values.get("data_category") or values.get("category") or line), values)
            attributes = {**values, "line": line}
            if values.get("trace_id"):
                self.trace_events.append(EvidenceRecord(
                    meta["file_id"], meta["file_path"], meta.get("captured_at", ""),
                    path.suffix.lstrip("."), str(system), str(resource), category,
                    time_value, attributes, "log_claim" if path.suffix.casefold() == ".log" else "text_claim"))
            if not resource:
                continue
            self.add(meta, path.suffix.lstrip("."), str(system), str(resource), category, time_value, attributes, "log_claim" if path.suffix.casefold() == ".log" else "text_claim")
    def _parse_pdf(self, meta: dict[str, str], path: Path) -> None:
        try:
            import fitz
            document = fitz.open(path)
        except Exception:
            return
        try:
            for page_no, page in enumerate(document, start=1):
                page_text = page.get_text()
                resources = sorted({m.group(0) for m in RESOURCE_PATTERN.finditer(page_text)})
                # Page text alone can make a customer-uploaded attachment look
                # like a shared support conversation. Include the participant
                # artifact's filename when identifying its evidence category.
                category = self._category(f"{path.stem} {page_text}", {})
                for resource in resources:
                    self.add(meta, "pdf", "", resource, category, meta.get("captured_at", ""), {"page": page_no, "text": page_text}, "document_claim")
        finally:
            document.close()

    def _parse_image(self, meta: dict[str, str], path: Path) -> None:
        try:
            cache_key = (str(path.resolve()), path.stat().st_mtime_ns)
            entries = self._image_text_cache.get(cache_key)
            if entries is None:
                if EvidenceCatalog._shared_ocr_engine is None:
                    from rapidocr_onnxruntime import RapidOCR
                    EvidenceCatalog._shared_ocr_engine = RapidOCR()
                result, _elapsed = EvidenceCatalog._shared_ocr_engine(str(path))
                entries = []
                for row in result or []:
                    if len(row) < 3 or not str(row[1]).strip() or float(row[2]) < 0.45:
                        continue
                    points = row[0]
                    ys = [float(point[1]) for point in points]
                    entries.append((str(row[1]).strip(), sum(ys) / len(ys), max(ys) - min(ys)))
                if not entries:
                    raise ValueError("OCR returned no confident text")
                self._image_text_cache[cache_key] = entries
        except ImportError:
            if meta["file_id"] not in self.unparsed_images:
                self.unparsed_images.append(meta["file_id"])
            return
        except Exception:
            if meta["file_id"] not in self.unparsed_images:
                self.unparsed_images.append(meta["file_id"])
            return

        full_text = "\n".join(item[0] for item in entries)
        category = self._category(full_text, {})
        for text, center_y, height in entries:
            resources = {
                match.group(0) for match in RESOURCE_PATTERN.finditer(text)
                if any(char.isdigit() for char in match.group(0).rsplit("_", 1)[-1])
            }
            for resource in resources:
                tolerance = max(18.0, height * 0.75)
                row_text = " ".join(item[0] for item in entries
                                    if abs(item[1] - center_y) <= max(tolerance, item[2] * 0.75))
                self.add(meta, "image", "", resource, category, meta.get("captured_at", ""),
                         {"text": row_text, "ocr_confidence_threshold": 0.45}, "screen_claim")


def table_to_system(table: str) -> str:
    normalized = table.casefold()
    for prefix, system in (
        ("customer_profiles", "account_service"), ("customer_search", "search_service"),
        ("customer_analytics", "analytics_platform"), ("customer_exports", "export_service"),
        ("connector_", "integration_service"), ("backup_", "backup_service"),
        ("security_", "security_service"), ("support_", "support_platform"),
    ):
        if normalized.startswith(prefix):
            return system
    return {
        "customer_profiles": "account_service",
        "customer_search_documents": "search_service",
        "customer_analytics_profiles": "analytics_platform",
        "customer_exports": "export_service",
        "connector_subscriptions": "integration_service",
        "backup_restore_entries": "backup_service",
        "security_audit_records": "security_service",
        "support_records": "support_platform",
    }.get(table, "")



def evidence_visible(record: EvidenceRecord, audit_at: str) -> bool:
    """Evidence is usable only when both its capture and record time meet the cutoff."""
    from datetime import datetime, timezone

    def parse(value: str):
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    cutoff = parse(audit_at)
    captured = parse(record.captured_at)
    observed = parse(record.observed_at) if record.observed_at else captured
    return bool(cutoff and captured and observed and captured <= cutoff and observed <= cutoff)


def matches_subject(record: EvidenceRecord, identifiers: dict[str, set[str]]) -> bool:
    """Match typed identifiers and explicit subject-reference fields, not file names."""
    from identity import normalize_identifier

    key_fields = {
        "email": ("email", "email_address", "owner_email", "requester_email", "customer_email"),
        "phone": ("phone", "phone_number", "mobile", "requester_phone", "owner_phone"),
        "email_hash": ("email_hash", "hash"),
        "name": ("name", "full_name", "display_name", "requester_name", "customer_name"),
    }
    ref_keys = {"user_id", "customer_reference", "subject_reference", "subject_ref", "user_ref", "stable_user_id"}
    text_keys = {"line", "message_excerpt", "message_text", "text", "page_text", "content", "details", "query", "lookup_key", "subject_key", "subject_identifier", "correlation_key", "matched_value", "selector"}
    all_values = {normalize_identifier(field, v) for field, values in identifiers.items() for v in values}
    all_values.discard("")
    user_values = {normalize_identifier("user_id", v) for v in identifiers.get("user_id", set())}
    email_values = {normalize_identifier("email", v) for v in identifiers.get("email", set())}
    phone_values = {normalize_identifier("phone", v) for v in identifiers.get("phone", set())}
    hash_values = {normalize_identifier("email_hash", v) for v in identifiers.get("email_hash", set())}
    name_values = {normalize_identifier("name", v) for v in identifiers.get("name", set())}

    def visit(value: Any, key: str = "") -> bool:
        if isinstance(value, dict):
            return any(visit(v, str(k).casefold()) for k, v in value.items())
        if isinstance(value, (list, tuple, set)):
            return any(visit(v, key) for v in value)
        if value is None:
            return False
        text = str(value).strip()
        if not text:
            return False
        normkey = key.casefold()
        if normkey in ref_keys or normkey.endswith("_reference") or normkey.endswith("_ref"):
            return normalize_identifier("user_id", text) in user_values
        if "email" in normkey:
            return normalize_identifier("email", text) in email_values
        if "phone" in normkey or "mobile" in normkey:
            return normalize_identifier("phone", text) in phone_values
        if "hash" in normkey:
            return normalize_identifier("email_hash", text) in hash_values
        if normkey in key_fields["name"] or normkey.endswith("_name"):
            return normalize_identifier("name", text) in name_values
        if normkey in text_keys or normkey.endswith("_text") or normkey in {"query", "selector"}:
            folded = text.casefold()
            if any(v and re.search(rf"(?<![a-z0-9]){re.escape(v)}(?![a-z0-9])", folded) for v in email_values | hash_values | user_values):
                return True
            digits = re.sub(r"\D", "", text)
            if any(v and len(v) >= 7 and v in digits for v in phone_values):
                return True
            if any(v and re.search(rf"(?<![\w]){re.escape(v)}(?![\w])", folded) for v in name_values):
                return True
        # Untyped keys sometimes hold a lookup value (e.g. identifier or selector).
        normalized = normalize_identifier("email", text)
        if "@" in normalized and normalized in email_values:
            return True
        if re.fullmatch(r"[0-9+(). -]{7,}", text) and normalize_identifier("phone", text) in phone_values:
            return True
        if re.fullmatch(r"[0-9a-fA-F]{64}", text) and normalize_identifier("email_hash", text) in hash_values:
            return True
        if re.fullmatch(r"user_[A-Za-z0-9-]+", text, re.I) and normalize_identifier("user_id", text) in user_values:
            return True
        return False

    return visit(record.attributes)
