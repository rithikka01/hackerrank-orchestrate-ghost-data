from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import re
import unicodedata
from typing import Iterable, Mapping, Any

IDENTITY_FIELDS = ("name", "email", "phone", "email_hash")


def normalize_identifier(field: str, value: Any) -> str:
    """Canonicalize a value for matching while retaining originals for evidence search."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value)).strip()
    if not text:
        return ""
    field = field.strip().casefold()
    if field == "email":
        return text.casefold()
    if field == "phone":
        return re.sub(r"\D", "", text)
    if field in {"email_hash", "user_id"}:
        return text.casefold()
    return " ".join(text.split()).casefold()


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _visible_by(timestamp: Any, cutoff: Any) -> bool:
    event_time = _parse_timestamp(timestamp)
    audit_time = _parse_timestamp(cutoff)
    return event_time is not None and audit_time is not None and event_time <= audit_time


class IdentityIndex:
    """Resolve a request identifier to a stable user_id using cutoff-visible data."""

    def __init__(
        self,
        identities: Iterable[Mapping[str, Any]],
        audit_events: Iterable[Mapping[str, Any]],
    ) -> None:
        self.identities: dict[str, dict[str, Any]] = {}
        self.audit_events: list[dict[str, Any]] = []
        for row in identities:
            user_id = str(row.get("user_id", "")).strip()
            if user_id:
                self.identities[user_id] = dict(row)
        for row in audit_events:
            user_id = str(row.get("user_id", "")).strip()
            field = str(row.get("field_name", "")).strip().casefold()
            if user_id and field in IDENTITY_FIELDS:
                self.audit_events.append(dict(row))

    def identifiers_for(self, user_id: str, audit_at: str) -> dict[str, set[str]]:
        """Return raw identifier spellings known by audit_at, grouped by field."""
        result: dict[str, set[str]] = {field: set() for field in IDENTITY_FIELDS}
        stable_id = str(user_id).strip()
        if not stable_id or _parse_timestamp(audit_at) is None:
            return result

        current = self.identities.get(stable_id)
        if current and _visible_by(current.get("updated_at"), audit_at):
            for field in IDENTITY_FIELDS:
                value = str(current.get(field, "")).strip()
                if normalize_identifier(field, value):
                    result[field].add(value)

        for event in self.audit_events:
            if str(event.get("user_id", "")).strip() != stable_id:
                continue
            if not _visible_by(event.get("event_time"), audit_at):
                continue
            field = str(event.get("field_name", "")).strip().casefold()
            for column in ("old_value", "new_value"):
                value = str(event.get(column, "")).strip()
                if normalize_identifier(field, value):
                    result[field].add(value)
        return result

    def resolve_email(self, email: str, audit_at: str) -> str | None:
        """Return one unambiguous subject; return None when absent or conflicting."""
        key = normalize_identifier("email", email)
        if not key or _parse_timestamp(audit_at) is None:
            return None
        candidates: set[str] = set()

        for user_id, row in self.identities.items():
            if not _visible_by(row.get("updated_at"), audit_at):
                continue
            if normalize_identifier("email", row.get("email")) == key:
                candidates.add(user_id)

        for event in self.audit_events:
            if event.get("field_name", "").strip().casefold() != "email":
                continue
            if not _visible_by(event.get("event_time"), audit_at):
                continue
            if any(normalize_identifier("email", event.get(column)) == key
                   for column in ("old_value", "new_value")):
                candidates.add(str(event["user_id"]).strip())

        return next(iter(candidates)) if len(candidates) == 1 else None

    def all_identifiers(self, user_id: str, audit_at: str) -> set[str]:
        """Flatten known identifier spellings for text/evidence matching."""
        grouped = self.identifiers_for(user_id, audit_at)
        values = {str(user_id).strip()} if str(user_id).strip() else set()
        for aliases in grouped.values():
            values.update(aliases)
        return values
