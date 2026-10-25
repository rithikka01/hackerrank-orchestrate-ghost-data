# Evaluation report

## Scope and limits

There is no supplied hidden-answer scoring program in `code/evaluation/main.py` (the file is empty). The metrics below are measured against the 32 public sample rows using the solution's current predictions and `dataset/sample_output.csv` strictly as an expected-output reference. The sample answers were not used as evidence or as prediction rules. These are sample-only diagnostics, not hidden-set accuracy estimates.

The latest full-dataset pipeline attempt processed 518 requests, produced 378 predictions, and stopped with 140 audit errors and one coverage validation error. It did not write root `output.csv`. Therefore, full-dataset accuracy against hidden answers is unavailable.

## Public sample metrics

The sample contains 32 cases and 193 expected steps. The pipeline returned 23 predictions, raised 9 audit errors, reported 14 output differences among the returned cases, and had one validation error for missing case coverage.

| Metric | Result | Definition |
|---|---:|---|
| Case status accuracy | 23/32 (71.9%) | Exact status matches over all sample cases; missing predictions count as incorrect. All 23 returned predictions had the expected status (23/23). |
| Exact row accuracy | 9/32 (28.1%) | Status and full ordered `steps_json` both match; missing predictions count as incorrect. |
| Exact sequence accuracy | 9/32 (28.1%) | The entire ordered step array matches for the case; missing predictions count as incorrect. |
| Exact step accuracy | 116/194 (59.8%) | Exact step objects at the same ordinal position, divided by aligned step slots. Missing expected steps and extra predicted steps count as incorrect slots. |
| Step-field accuracy | 913/1,358 (67.2%) | Exact field values over seven step fields per aligned slot. Missing fields/steps and extra slots count as incorrect. |
| Coverage | 23/32 predictions | The other 9 cases raised audit errors; the output validator consequently reported a coverage error. |

The field metric uses `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id`. It is a diagnostic definition for this report, not a claim about the hidden evaluator's metric implementation.

## Additional participant-created evaluation cases

These regression cases are implemented in the unit suite and passed in the latest 51-test run:

1. **Typed resource reference:** follow an explicit `source_resource_id` only when its target is unambiguous and cutoff-valid.
2. **Missing or ambiguous reference:** do not invent a target or traverse a reference with conflicting target systems.
3. **Reference cycle and cutoff:** terminate traversal through a cycle and do not use a target observed after `audit_at`.

The unit tests also cover structured JSON logs, nested escaped log fields, explicit JSON `record_type` and `recorded_at`, and rejection of an OCR-derived destination label as a resource ID.

## Failures found and improvements made

- The parser originally missed nested escaped key/value fields in an observability log. It now parses those fields while preserving file provenance and timestamps.
- JSON exports with generic `records` collections could carry a supported category in `record_type`; this is now recognized. `recorded_at` is now used as the observation time, with the independent manifest capture cutoff still enforced.
- OCR previously treated `analytics_warehouse` as a resource ID. OCR now applies the same numeric-suffix check used for text logs.
- The latest full run still has 140 unresolved cases: 127 lack evidence establishing account-profile state, and 13 have no usable cutoff-valid linked evidence. The solution fails closed and withholds `output.csv` rather than inventing statuses, findings, or verification steps.

## Current verification

- Unit tests: **51 passed, 0 failed**.
- Full pipeline: **378/518 predictions**, 140 audit errors, 1 coverage validation error; output not written.
- Sample diagnostic: **23/32 predictions**, 9 audit errors, 14 differences, 1 coverage validation error.
- Hidden-answer accuracy: **not available** in the supplied repository.
