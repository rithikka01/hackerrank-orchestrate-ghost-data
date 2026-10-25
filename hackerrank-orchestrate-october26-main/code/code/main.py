from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import Any

CODE_DIR = Path(__file__).resolve().parent
REPO_ROOT = CODE_DIR.parent
DATASET_DIR = REPO_ROOT / "dataset"
sys.path.insert(0, str(CODE_DIR))

from audit import AuditEngine, read_csv  # noqa: E402
from validation import validate_predictions  # noqa: E402


def _run_rows(engine: AuditEngine, requests: list[dict[str, str]]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    predictions: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for request in requests:
        try:
            predictions.append(engine.audit_one(request))
        except Exception as exc:
            errors[request["case_id"]] = str(exc)
    predictions.sort(key=lambda row: row["case_id"])
    return predictions, errors


def _sample_mismatches(predictions: list[dict[str, Any]], sample_output: list[dict[str, str]]) -> list[str]:
    expected = {
        row["case_id"]: (row["deletion_status"], json.loads(row["steps_json"]))
        for row in sample_output
    }
    actual = {row["case_id"]: row for row in predictions}
    mismatches = []
    for case_id, (status, steps) in expected.items():
        row = actual.get(case_id)
        if row is None:
            continue
        if row["deletion_status"] != status or row["steps"] != steps:
            mismatches.append(case_id)
    return mismatches


def _serialize(predictions: list[dict[str, Any]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
    writer.writeheader()
    for row in predictions:
        writer.writerow({
            "case_id": row["case_id"],
            "deletion_status": row["deletion_status"],
            "steps_json": json.dumps(row["steps"], ensure_ascii=False, separators=(",", ":")),
        })
    return stream.getvalue()


def main() -> int:
    engine = AuditEngine(DATASET_DIR)
    if engine.catalog.unparsed_images:
        print(f"ERROR: could not parse {len(engine.catalog.unparsed_images)} image evidence files; install code/requirements.txt")
        return 1
    valid_evidence_ids = engine.evidence_ids
    all_requests = read_csv(DATASET_DIR / "deletion_requests.csv")
    sample_requests = read_csv(DATASET_DIR / "sample_deletion_requests.csv")
    expected_sample = read_csv(DATASET_DIR / "sample_output.csv")
    sample_predictions, sample_errors = _run_rows(engine, sample_requests)
    sample_validation = validate_predictions(sample_predictions, sample_requests, valid_evidence_ids)
    sample_mismatches = _sample_mismatches(sample_predictions, expected_sample)
    print(f"Sample gate: {len(sample_predictions)}/{len(sample_requests)} predictions; "
          f"{len(sample_errors)} audit errors; {len(sample_mismatches)} sample mismatches; "
          f"{len(sample_validation)} contract errors")
    if sample_errors:
        for case_id, error in sorted(sample_errors.items()):
            print(f"  {case_id}: {error}")
    if sample_mismatches:
        print("  Sample output differs for: " + ", ".join(sample_mismatches))
    if sample_validation:
        for error in sample_validation:
            print("  Validation: " + error)
    if sample_errors or sample_mismatches or sample_validation:
        print("Sample results are diagnostic only; proceeding to the full request set. "
              "The full output will still be withheld if any audit or contract check fails.")

    requests = all_requests
    predictions, errors = _run_rows(engine, requests)
    validation_errors = validate_predictions(predictions, requests, valid_evidence_ids)
    from collections import Counter
    status_counts = Counter(row["deletion_status"] for row in predictions)
    print(f"Full run: {len(predictions)}/{len(requests)} predictions; {len(errors)} audit errors; "
          f"{len(validation_errors)} contract errors; status distribution={dict(sorted(status_counts.items()))}")
    if errors or validation_errors:
        print(f"Full run stopped: {len(errors)} audit errors, {len(validation_errors)} contract errors; output.csv was not written.")
        for case_id, error in sorted(errors.items()):
            print(f"  {case_id}: {error}")
        for error in validation_errors:
            print("  Validation: " + error)
        return 1

    output_path = REPO_ROOT / "output.csv"
    output_path.write_text(_serialize(predictions), encoding="utf-8", newline="")
    print(f"Wrote {len(predictions)} validated predictions to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
