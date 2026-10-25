from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from evidence import EvidenceCatalog, EvidenceRecord, evidence_visible, matches_subject
from identity import IdentityIndex, normalize_identifier
from intent import RequestIntent, classify_request
from policy import PolicyBook

STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
ALLOWED = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}
OPERATION_ORDER = {
    "FINDING": list(ALLOWED["FINDING"]),
    "REMEDIATION": list(ALLOWED["REMEDIATION"]),
    "VERIFICATION": list(ALLOWED["VERIFICATION"]),
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def _time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _field_values(value: Any, key: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from _field_values(child, str(child_key).casefold())
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            yield from _field_values(child, key)
    else:
        yield key, value


def has_direct_identifier(record: EvidenceRecord, identifiers: dict[str, set[str]]) -> bool:
    direct = {k: set(v) for k, v in identifiers.items() if k in {"name", "email", "phone", "email_hash"}}
    return matches_subject(record, direct)


def has_subject_reference(record: EvidenceRecord, user_id: str) -> bool:
    return matches_subject(record, {"user_id": {user_id}})


def _state(record: EvidenceRecord) -> str:
    attrs = record.attributes
    if record.evidence_kind == "query" and isinstance(attrs.get("hits"), list):
        return "PRESENT" if attrs["hits"] else "ABSENT"
    if "status_code" in attrs:
        try:
            code = int(attrs["status_code"])
        except (TypeError, ValueError):
            code = None
        if code == 404:
            return "ABSENT"
        if code == 200:
            return "PRESENT"
    if attrs.get("enabled") is not None and record.category == "DATA_FLOW":
        return "ACTIVE" if _truth(attrs["enabled"]) else "DISABLED"
    if attrs.get("restore_allowed") is not None and record.category == "BACKUP_ARCHIVE":
        return "ACTIVE" if _truth(attrs["restore_allowed"]) else "BLOCKED"
    if record.category == "BACKUP_ARCHIVE" and "eligible" in attrs:
        if _truth(attrs.get("deletion_block")):
            return "BLOCKED"
        return "ACTIVE" if _truth(attrs.get("eligible")) else "BLOCKED"

    states = {"PRESENT", "FOUND", "IDENTIFIABLE", "ACTIVE", "ABSENT", "NOT_FOUND", "DELETED", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"}
    for key in ("state", "record_state", "lookup_result", "result_state", "status"):
        value = str(attrs.get(key, "")).strip().upper().replace(" ", "_")
        if value in states:
            if value in {"FOUND", "IDENTIFIABLE"}:
                return "PRESENT"
            if value == "NOT_FOUND":
                return "ABSENT"
            return value
    try:
        row_count = int(attrs.get("rows", ""))
    except (TypeError, ValueError):
        row_count = None
    event_name = str(attrs.get("event", "")).casefold()
    if row_count is not None and row_count > 0 and event_name.endswith("_completed"):
        return "PRESENT"
    if str(attrs.get("http_status", "")) == "404" or str(attrs.get("rows", "")) == "0":
        return "ABSENT"
    result = str(attrs.get("result", "")).casefold()
    if result in {"hit", "found", "match"}:
        return "PRESENT"
    if result in {"miss", "not_found", "no_match"}:
        return "ABSENT"
    if attrs.get("matched_value") and attrs.get("detector"):
        return "PRESENT"
    if record.source_format in {"json", "sql", "pdf", "image"} and record.evidence_kind in {"snapshot", "screen_claim", "document_claim", "record"}:
        return "PRESENT"
    return "UNKNOWN"


def _truth(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "active", "enabled", "allowed"}


RESOURCE_SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "analytics": "analytics_platform",
    "backup": "backup_service",
    "data": "integration_service",
    "email": "email_delivery_service",
    "export": "export_service",
    "search": "search_service",
    "support": "support_platform",
    "audit": "security_service",
    "tombstone": "identity_service",
    "cache": "cache_service",
    "secondary": "identity_service",
    "telemetry": "analytics_platform",
}
RESOURCE_ID_VALUE = re.compile(
    r"^(?:account|analytics|backup|data_flow|email_delivery|export|search|support|audit_record|tombstone|cache|secondary_identifier|telemetry|attachment|invoice|order)_[A-Za-z0-9-]+$",
    re.IGNORECASE,
)


def _system_for(record: EvidenceRecord) -> str:
    if record.system_id:
        return record.system_id
    return _system_for_resource_id(record.resource_id)


def _system_for_resource_id(resource_id: str) -> str:
    prefix = str(resource_id).split("_", 1)[0].casefold()
    return RESOURCE_SYSTEM_BY_PREFIX.get(prefix, "")


def _typed_resource_references(attributes: Any) -> set[str]:
    """Extract only explicitly typed resource pointer fields, never arbitrary text."""
    found: set[str] = set()
    for key, value in _field_values(attributes):
        normalized_key = key.casefold()
        if normalized_key == "resource_id" or not (
            normalized_key.endswith("_resource_id") or normalized_key.endswith("_resource_ids")
        ):
            continue
        candidate = str(value).strip()
        if RESOURCE_ID_VALUE.fullmatch(candidate):
            found.add(candidate)
    return found


class AuditEngine:
    def __init__(self, dataset_dir: str | Path):
        self.dataset_dir = Path(dataset_dir)
        self.identities = IdentityIndex(
            read_csv(self.dataset_dir / "user_identities.csv"),
            read_csv(self.dataset_dir / "user_audit_log.csv"),
        )
        self.catalog = EvidenceCatalog(self.dataset_dir).load()
        self.rules = PolicyBook.from_csv(self.dataset_dir / "deletion_rules.csv")
        self.activities = read_csv(self.dataset_dir / "system_activity.csv")
        self.activity_ids = {row["activity_id"] for row in self.activities}
        self.audit_ids = {row["audit_id"] for row in read_csv(self.dataset_dir / "user_audit_log.csv")}
        self.evidence_ids = set(self.catalog.manifest) | self.activity_ids | self.audit_ids

    def _identifiers(self, user_id: str, audit_at: str) -> dict[str, set[str]]:
        grouped = self.identities.identifiers_for(user_id, audit_at)
        grouped["user_id"] = {user_id}
        return grouped

    def _snapshot_absence_records(self, resource_ids: set[str], audit_at: str) -> list[EvidenceRecord]:
        """Use absence only from a complete, time-valid profile table snapshot."""
        result: list[EvidenceRecord] = []
        for scope in self.catalog.scopes:
            if not scope["complete"] or scope["category"] != "USER_PROFILE":
                continue
            visible = EvidenceRecord(scope["file_id"], scope["file_path"], scope["captured_at"], "sql",
                                     scope["system_id"], "", scope["category"], scope["observed_at"], {}, "snapshot_scope")
            if not evidence_visible(visible, audit_at):
                continue
            existing = {r.resource_id for r in self.catalog.records
                        if r.file_id == scope["file_id"] and r.category == "USER_PROFILE"
                and r.attributes.get("snapshot_table") == scope["table"]}
            for resource in sorted(resource_ids):
                if resource.startswith("account_") and resource not in existing:
                    result.append(EvidenceRecord(
                        scope["file_id"], scope["file_path"], scope["captured_at"], "sql",
                        scope["system_id"] or "account_service", resource, "USER_PROFILE",
                        scope["observed_at"], {"state": "ABSENT", "resource_id": resource, "snapshot_table": scope["table"]}, "snapshot_absence"))
        return result
    def _resource_links(self, identifiers: dict[str, set[str]], audit_at: str) -> set[str]:
        linked: set[str] = set()
        visible_records = [record for record in self.catalog.records if evidence_visible(record, audit_at)]
        by_resource: dict[str, list[EvidenceRecord]] = defaultdict(list)
        for record in visible_records:
            if record.resource_id:
                by_resource[record.resource_id].append(record)

        # Begin only with records directly grounded in this person's cutoff-visible identifiers.
        frontier: list[EvidenceRecord] = []
        for record in visible_records:
            if matches_subject(record, identifiers):
                linked.add(record.resource_id)
                frontier.append(record)

        linked_traces = {
            (event.file_id, str(event.attributes.get("trace_id")))
            for event in self.catalog.trace_events
            if evidence_visible(event, audit_at) and event.attributes.get("trace_id")
            and matches_subject(event, identifiers)
        }
        if linked_traces:
            for record in visible_records:
                key = (record.file_id, str(record.attributes.get("trace_id", "")))
                if key in linked_traces and record.resource_id:
                    linked.add(record.resource_id)
                    frontier.append(record)

        # Follow explicit resource pointers (for example source_resource_id) from
        # already-linked evidence. Use cutoff-visible target records only. When a
        # target is absent, a known resource prefix still grounds its ID/system;
        # a complete snapshot may then prove absence. Conflicting target systems
        # are treated as ambiguous and are not traversed.
        visited: set[int] = set()
        while frontier:
            source = frontier.pop()
            if id(source) in visited:
                continue
            visited.add(id(source))
            for resource_id in _typed_resource_references(source.attributes):
                candidates = by_resource.get(resource_id, [])
                prefix_system = _system_for_resource_id(resource_id)
                candidate_systems = {_system_for(candidate) for candidate in candidates}
                if prefix_system:
                    if candidate_systems and candidate_systems != {prefix_system}:
                        continue
                    target_system = prefix_system
                elif len(candidate_systems) == 1 and "" not in candidate_systems:
                    target_system = next(iter(candidate_systems))
                else:
                    # No target and no reliable system, or conflicting candidates.
                    continue
                linked.add(resource_id)
                for candidate in candidates:
                    if _system_for(candidate) == target_system and id(candidate) not in visited:
                        frontier.append(candidate)

        cutoff = _time(audit_at)
        for row in self.activities:
            event_time = _time(row.get("event_time"))
            if cutoff is None or event_time is None or event_time > cutoff:
                continue
            activity_record = EvidenceRecord(
                file_id=row.get("activity_id", ""),
                file_path="system_activity.csv",
                captured_at=row.get("event_time", ""),
                source_format="activity",
                system_id=row.get("target_system", "") or row.get("source_system", ""),
                resource_id=row.get("resource_id", ""),
                category="UNKNOWN",
                observed_at=row.get("event_time", ""),
                attributes=row,
                evidence_kind="activity_claim",
            )
            if activity_record.resource_id and matches_subject(activity_record, identifiers):
                linked.add(activity_record.resource_id)
        return linked

    def _latest_subject_records(self, resource_ids: set[str], audit_at: str) -> list[EvidenceRecord]:
        groups: dict[tuple[str, str, str, str], list[EvidenceRecord]] = defaultdict(list)
        for record in self.catalog.records:
            if record.resource_id not in resource_ids or not evidence_visible(record, audit_at):
                continue
            if record.category == "UNKNOWN":
                continue
            groups[(_system_for(record), record.resource_id, record.category, record.attributes.get("snapshot_table", ""))].append(record)
        selected: list[EvidenceRecord] = []
        for entries in groups.values():
            latest_capture = max(_time(item.captured_at) for item in entries if _time(item.captured_at) is not None)
            current = [item for item in entries if _time(item.captured_at) == latest_capture]
            # A positive record in any current replica is a violation; retain all tied
            # observations so conflicts fail conservatively instead of hiding drift.
            selected.extend(current)
        return selected

    def audit_one(self, request: dict[str, str]) -> dict[str, Any]:
        case_id = request["case_id"]
        audit_at = request["audit_at"]
        intent = classify_request(request.get("request_text", ""))
        if intent == RequestIntent.NOT_DELETION:
            return {"case_id": case_id, "deletion_status": "NOT_APPLICABLE", "steps": []}
        if intent == RequestIntent.UNCERTAIN:
            raise ValueError(f"Cannot determine deletion authorization for {case_id}")
        user_id = self.identities.resolve_email(request.get("email", ""), audit_at)
        if user_id is None:
            raise ValueError(f"Identity is unresolved or ambiguous for {case_id}")
        identifiers = self._identifiers(user_id, audit_at)
        resource_ids = self._resource_links(identifiers, audit_at)
        records = self._latest_subject_records(resource_ids, audit_at)
        records.extend(self._snapshot_absence_records(resource_ids, audit_at))
        if not records:
            raise ValueError(f"No time-valid evidence was linked to {case_id}")

        findings: list[dict[str, Any]] = []
        remediations: list[dict[str, Any]] = []
        complete_verifications: list[dict[str, Any]] = []
        incomplete_verifications: list[dict[str, Any]] = []
        is_incomplete = False
        has_account_state = False

        def step(phase: str, system: str, resource: str, operation: str, state: str, evidence_id: str) -> dict[str, Any]:
            return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource,
                    "operation": operation, "state": state, "evidence_id": evidence_id}

        def add_verification(target: list[dict[str, Any]], system: str, resource: str, operation: str, state: str, evidence: str = "") -> None:
            target.append(step("VERIFICATION", system, resource, operation, state, evidence))

        grouped: dict[tuple[str, str, str, str], list[EvidenceRecord]] = defaultdict(list)
        for record in records:
            grouped[(_system_for(record), record.resource_id, record.category, record.attributes.get("snapshot_table", ""))].append(record)

        for (system, resource, category, _snapshot_table), observations in grouped.items():
            observations.sort(key=lambda r: (_time(r.captured_at) or datetime.min.replace(tzinfo=timezone.utc), r.file_id))
            # Exact-capture ties are independent copies/readbacks. Keep any PRESENT
            # observation over an ABSENT one; this is intentionally conservative.
            current = [r for r in observations if _time(r.captured_at) == _time(observations[-1].captured_at)]
            state_priority = {"PRESENT": 4, "ACTIVE": 4, "ABSENT": 3, "DISABLED": 3, "BLOCKED": 3, "REDACTED": 3, "ANONYMIZED": 3, "UNKNOWN": 1}
            picked = sorted(current, key=lambda r: (state_priority.get(_state(r), 0), r.source_format in {"json", "sql"}, r.file_id), reverse=True)
            record = picked[0]
            state = _state(record)
            if category == "USER_PROFILE":
                has_account_state = has_account_state or state in {"ABSENT", "PRESENT", "ACTIVE"}
            direct = has_direct_identifier(record, identifiers)
            linked_ref = has_subject_reference(record, user_id)
            action = self.rules.required_action(category, record.attributes, audit_at,
                                                linked_to_subject=True,
                                                direct_identifier_present=direct)
            system = system or _system_for(record)

            violation: tuple[str, str, str, str] | None = None
            if category == "DATA_FLOW":
                if state == "ACTIVE":
                    violation = ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLE_DATA_FLOW", "DISABLED")
                    add_verification(incomplete_verifications, system, resource, "VERIFY_DATA_FLOW_DISABLED", "DISABLED")
                elif state == "DISABLED":
                    add_verification(complete_verifications, system, resource, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", record.file_id)
            elif category == "BACKUP_ARCHIVE":
                if state == "ACTIVE":
                    violation = ("REPORT_RESTORE_RISK", "ACTIVE", "BLOCK_RESTORE", "BLOCKED")
                    add_verification(incomplete_verifications, system, resource, "VERIFY_RESTORE_BLOCKED", "BLOCKED")
                elif state == "BLOCKED":
                    add_verification(complete_verifications, system, resource, "VERIFY_RESTORE_BLOCKED", "BLOCKED", record.file_id)
            elif action == "DELETE":
                if state == "ABSENT":
                    add_verification(complete_verifications, system, resource, "VERIFY_RECORD_ABSENT", "ABSENT", record.file_id)
                    add_verification(incomplete_verifications, system, resource, "VERIFY_RECORD_ABSENT", "ABSENT")
                elif state in {"PRESENT", "ACTIVE", "UNKNOWN"}:
                    violation = ("REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT")
            elif action == "REDACT":
                if direct:
                    violation = ("REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED")
                else:
                    add_verification(complete_verifications, system, resource, "VERIFY_RECORD_REDACTED", "REDACTED", record.file_id)
                    add_verification(incomplete_verifications, system, resource, "VERIFY_RECORD_REDACTED", "REDACTED")
            elif action == "ANONYMIZE":
                if direct or linked_ref:
                    violation = ("REPORT_EXPOSED_PII", "PRESENT", "ANONYMIZE_RECORD", "ANONYMIZED")
                else:
                    add_verification(complete_verifications, system, resource, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", record.file_id)
                    add_verification(incomplete_verifications, system, resource, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")
            elif action == "RETAIN":
                if state == "PRESENT":
                    add_verification(complete_verifications, system, resource, "VERIFY_RECORD_PRESENT", "PRESENT", record.file_id)
                    add_verification(incomplete_verifications, system, resource, "VERIFY_RECORD_PRESENT", "PRESENT")
                elif state == "ABSENT":
                    # The allowed vocabulary has no missing-retained-record finding.
                    # Stop rather than silently call the deletion complete.
                    raise ValueError(f"Required retained record is absent for {case_id}: {resource}")

            if violation:
                is_incomplete = True
                finding_operation, finding_state, remediation_operation, remediation_state = violation
                findings.append(step("FINDING", system, resource, finding_operation, finding_state, record.file_id))
                remediations.append(step("REMEDIATION", system, resource, remediation_operation, remediation_state, ""))
                verify_op = {
                    "DELETE_RECORD": "VERIFY_RECORD_ABSENT",
                    "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
                    "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
                }.get(remediation_operation)
                if verify_op:
                    add_verification(incomplete_verifications, system, resource, verify_op, remediation_state)

        # A proven surviving record is sufficient to establish INCOMPLETE even
        # when the account's own profile cannot be linked. Do not invent an
        # account resource or claim its absence in that situation. For an
        # otherwise complete result, an explicit account state remains required.
        if not has_account_state and not is_incomplete:
            raise ValueError(f"No explicit account presence/absence evidence for {case_id}")
        phase_steps = findings + remediations + (incomplete_verifications if is_incomplete else complete_verifications)
        if is_incomplete and (not findings or not remediations or not incomplete_verifications):
            raise ValueError(f"Incomplete case lacks a full remediation/verification plan: {case_id}")
        dedup: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for item in phase_steps:
            key = (item["phase"], item["system_id"], item["resource_id"], item["operation"])
            existing = dedup.get(key)
            if existing is None or (not existing["evidence_id"] and item["evidence_id"]):
                dedup[key] = item
        ordered = sorted(dedup.values(), key=lambda x: (
            PHASE_ORDER[x["phase"]], OPERATION_ORDER[x["phase"]].index(x["operation"]), x["system_id"], x["resource_id"]
        ))
        for number, item in enumerate(ordered, start=1):
            item["step_no"] = number
        return {"case_id": case_id, "deletion_status": "INCOMPLETE" if is_incomplete else "COMPLETE", "steps": ordered}

    def audit_many(self, requests: list[dict[str, str]]) -> list[dict[str, Any]]:
        return [self.audit_one(row) for row in requests]


def validate_rows(rows: list[dict[str, Any]], expected_case_ids: list[str], valid_evidence_ids: set[str]) -> None:
    if [row["case_id"] for row in rows] != sorted(expected_case_ids):
        raise ValueError("Output rows are missing, duplicated, or not sorted by case_id")
    if len(rows) != len(expected_case_ids) or set(row["case_id"] for row in rows) != set(expected_case_ids):
        raise ValueError("Output case coverage does not match requests")
    for row in rows:
        status, steps = row["deletion_status"], row["steps"]
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"} or not isinstance(steps, list):
            raise ValueError(f"Invalid row status/steps: {row['case_id']}")
        if status == "NOT_APPLICABLE" and steps:
            raise ValueError(f"NOT_APPLICABLE must have no steps: {row['case_id']}")
        if status == "COMPLETE" and any(s["phase"] != "VERIFICATION" for s in steps):
            raise ValueError(f"COMPLETE may contain only verification steps: {row['case_id']}")
        if status == "INCOMPLETE" and not all(any(s["phase"] == p for s in steps) for p in ("FINDING", "REMEDIATION", "VERIFICATION")):
            raise ValueError(f"INCOMPLETE needs findings, remediation, and verification: {row['case_id']}")
        for number, step_item in enumerate(steps, start=1):
            if set(step_item) != STEP_FIELDS or step_item["step_no"] != number:
                raise ValueError(f"Invalid step schema/number in {row['case_id']}")
            if step_item["operation"] not in ALLOWED.get(step_item["phase"], {}) or ALLOWED[step_item["phase"]][step_item["operation"]] != step_item["state"]:
                raise ValueError(f"Invalid operation/state pair in {row['case_id']}")
            evidence_id = step_item["evidence_id"]
            if step_item["phase"] == "FINDING" or (status == "COMPLETE" and step_item["phase"] == "VERIFICATION"):
                if evidence_id not in valid_evidence_ids:
                    raise ValueError(f"Invalid evidence reference in {row['case_id']}")
            elif evidence_id != "":
                raise ValueError(f"Future step must have empty evidence_id in {row['case_id']}")
        expected = sorted(steps, key=lambda x: (
            PHASE_ORDER[x["phase"]], OPERATION_ORDER[x["phase"]].index(x["operation"]), x["system_id"], x["resource_id"]
        ))
        if steps != expected:
            raise ValueError(f"Step ordering is invalid in {row['case_id']}")


def serialize_steps(steps: list[dict[str, Any]]) -> str:
    return json.dumps(steps, ensure_ascii=False, separators=(",", ":"))
