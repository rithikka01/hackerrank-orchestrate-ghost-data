from __future__ import annotations

from typing import Any

from audit import ALLOWED, OPERATION_ORDER, PHASE_ORDER, STEP_FIELDS


def validate_predictions(
    predictions: list[dict[str, Any]],
    requests: list[dict[str, str]],
    evidence_ids: set[str],
) -> list[str]:
    """Return contract violations without changing or repairing predictions."""
    errors: list[str] = []
    expected_ids = sorted(row["case_id"] for row in requests)
    actual_ids = [row.get("case_id", "") for row in predictions]
    if len(actual_ids) != len(set(actual_ids)):
        errors.append("duplicate case_id in predictions")
    if actual_ids != expected_ids:
        errors.append("prediction case_id values must exactly match sorted request case_ids")

    for prediction in predictions:
        case_id = str(prediction.get("case_id", "<missing>"))
        status = prediction.get("deletion_status")
        steps = prediction.get("steps")
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            errors.append(f"{case_id}: invalid deletion_status {status!r}")
            continue
        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps must be a JSON array")
            continue
        if status == "NOT_APPLICABLE":
            if steps:
                errors.append(f"{case_id}: NOT_APPLICABLE must have no steps")
            continue
        if status == "COMPLETE" and not steps:
            errors.append(f"{case_id}: COMPLETE requires evidence-backed verification steps")
        if status == "INCOMPLETE":
            phases = {step.get("phase") for step in steps if isinstance(step, dict)}
            if not {"FINDING", "REMEDIATION", "VERIFICATION"}.issubset(phases):
                errors.append(f"{case_id}: INCOMPLETE requires findings, remediation, and verification")

        previous_key = None
        observed_phases: list[str] = []
        for number, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(f"{case_id}: step {number} must be an object")
                continue
            if set(step) != STEP_FIELDS:
                errors.append(f"{case_id}: step {number} fields must be exactly {sorted(STEP_FIELDS)}")
                continue
            if step["step_no"] != number:
                errors.append(f"{case_id}: step_no must be consecutive starting at 1")
            phase, operation, state = step["phase"], step["operation"], step["state"]
            if phase not in ALLOWED or ALLOWED[phase].get(operation) != state:
                errors.append(f"{case_id}: invalid phase/operation/state at step {number}")
                continue
            if phase not in observed_phases:
                observed_phases.append(phase)
            if status == "COMPLETE" and phase != "VERIFICATION":
                errors.append(f"{case_id}: COMPLETE may contain only verification steps")
            evidence_id = step["evidence_id"]
            if phase == "FINDING":
                if not evidence_id or evidence_id not in evidence_ids:
                    errors.append(f"{case_id}: finding step {number} must cite a valid evidence ID")
            elif status == "COMPLETE":
                if not evidence_id or evidence_id not in evidence_ids:
                    errors.append(f"{case_id}: COMPLETE verification step {number} must cite evidence")
            elif evidence_id:
                errors.append(f"{case_id}: remediation/future verification evidence_id must be empty")
            if not isinstance(step["system_id"], str) or not step["system_id"]:
                errors.append(f"{case_id}: step {number} needs a system_id")
            if not isinstance(step["resource_id"], str) or not step["resource_id"]:
                errors.append(f"{case_id}: step {number} needs a resource_id")
            key = (PHASE_ORDER[phase], OPERATION_ORDER[phase].index(operation), step["system_id"], step["resource_id"])
            if previous_key is not None and key < previous_key:
                errors.append(f"{case_id}: steps are out of required phase/operation/system/resource order")
            previous_key = key
        if observed_phases != sorted(observed_phases, key=PHASE_ORDER.__getitem__):
            errors.append(f"{case_id}: phases must be FINDING, REMEDIATION, VERIFICATION order")
    return errors
