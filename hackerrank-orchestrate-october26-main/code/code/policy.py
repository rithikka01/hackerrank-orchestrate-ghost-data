from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


class PolicyBook:
    """Load the challenge's policy table and apply its named conditions."""

    def __init__(self, rules: list[DeletionRule]):
        self.rules = {rule.data_category: rule for rule in rules}
        if len(self.rules) != len(rules):
            raise ValueError("Deletion policy contains duplicate categories")

    @classmethod
    def from_csv(cls, path: str | Path) -> "PolicyBook":
        with Path(path).open(encoding="utf-8-sig", newline="") as stream:
            rows = csv.DictReader(stream)
            expected = {"rule_id", "data_category", "condition", "required_action"}
            if set(rows.fieldnames or ()) != expected:
                raise ValueError("Unexpected deletion_rules.csv columns")
            rules = [DeletionRule(**{k: row[k].strip() for k in expected}) for row in rows]
        if len(rules) != 15:
            raise ValueError(f"Expected 15 deletion rules; found {len(rules)}")
        return cls(rules)

    def required_action(
        self,
        category: str,
        record: Mapping[str, Any],
        audit_at: str,
        *,
        linked_to_subject: bool,
        direct_identifier_present: bool,
    ) -> str | None:
        rule = self.rules.get(category)
        if rule is None:
            return None
        condition = rule.condition.casefold()
        if condition == "always":
            return rule.required_action
        if category == "SUPPORT_MESSAGE":
            if not linked_to_subject:
                return None
            # When context is undocumented, preserve the conversation and remove PII.
            # Delete only when evidence explicitly says the message belongs solely to
            # this subject; shared context must remain under the supplied rule.
            if _truthy(record.get("subject_only", record.get("belongs_only_to_subject"))):
                return "DELETE"
            return rule.required_action
        if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            return rule.required_action if linked_to_subject else None
        if category == "EMAIL_DELIVERY_LOG":
            return rule.required_action if direct_identifier_present else None
        if category == "SECURITY_AUDIT_LOG":
            retention = _parse_time(record.get("retention_until"))
            cutoff = _parse_time(audit_at)
            if retention is None or cutoff is None:
                return "RETAIN" if linked_to_subject else None
            return rule.required_action if retention >= cutoff else "DELETE"
        if category == "LEGAL_HOLD_RECORD":
            active = _truthy(record.get("active", record.get("hold_active", record.get("legal_hold_active"))))
            return rule.required_action if active else "DELETE"
        if category == "BACKUP_ARCHIVE":
            # The rule allows retention if restores can be blocked. An enabled restore
            # path still needs a BLOCK_RESTORE remediation before deletion can close.
            can_block = _truthy(record.get("restore_blockable", record.get("can_block_restore", True)))
            return rule.required_action if can_block else "DELETE"
        if category == "ACCOUNT_TOMBSTONE":
            return rule.required_action if linked_to_subject else None
        if category == "SUPPORT_ATTACHMENT":
            belongs_only_to_subject = _truthy(record.get("subject_only", record.get("belongs_only_to_subject", linked_to_subject)))
            return rule.required_action if belongs_only_to_subject else None
        return None


def _parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().casefold() in {"1", "true", "yes", "active", "enabled", "allowed"}
