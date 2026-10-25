# Evaluation report

## Scope and limits

The supplied `code/evaluation/main.py` is empty, so no hidden-answer scoring program is available. Sample metrics below compare the current solution against the 32 public rows in `dataset/sample_output.csv`. Those answers were used only as an expected-output reference, not as prediction evidence or rules. Sample metrics do not estimate hidden-set accuracy.

The final full-pipeline attempt read all 518 requests and produced 376 predictions. It stopped with 142 audit errors and one coverage validation error; root `output.csv` was not written. Hidden-answer accuracy is unavailable.

## Public sample metrics

The sample has 32 cases and 193 expected steps. The latest run returned 23 predictions, raised 9 audit errors, found 14 differences among returned cases, and reported one coverage error because predictions did not cover every case.

| Metric | Result | Definition |
|---|---:|---|
| Case status accuracy | 23/32 (71.9%) | Exact status matches across all sample cases; missing predictions count as incorrect. All returned predictions had the expected status (23/23). |
| Exact row accuracy | 9/32 (28.1%) | Status and full ordered `steps_json` match; missing predictions count as incorrect. |
| Exact sequence accuracy | 9/32 (28.1%) | The complete ordered step array matches; missing predictions count as incorrect. |
| Exact step accuracy | 116/194 (59.8%) | Exact step objects at the same ordinal position divided by aligned step slots. Missing and extra steps count as incorrect slots. |
| Step-field accuracy | 913/1,358 (67.2%) | Exact values across the seven step fields over aligned slots; missing and extra slots count as incorrect. |
| Coverage | 23/32 predictions | Nine sample requests raised audit errors; validation then reported missing case coverage. |

The field metric covers `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id`. It is a report diagnostic, not a claim about the hidden evaluator's implementation.

## Additional participant-created evaluation cases

The 53-test unit suite includes these regression cases, all passing:

1. **Typed resource references:** follow an explicit `source_resource_id` only when its target is unambiguous and visible by `audit_at`.
2. **Missing or ambiguous reference targets:** retain uncertainty instead of inventing a target or traversing conflicting systems.
3. **Reference cycles and cutoff:** terminate cyclic traversal and reject a target observed after `audit_at`.
4. **Mixed-category OCR rows:** classify each image resource using its row and typed resource prefix, including `data_flow_…` beside unrelated analytics text.
5. **Ambiguous image category text:** fail closed deterministically when a row names multiple categories.

Other tests cover structured JSON logs, nested escaped log fields, explicit JSON `record_type` and `recorded_at`, OCR provenance, and rejection of destination labels as resource IDs.

## Failures found and improvements made

- Structured log parsing now retains nested key/value fields, source provenance, and observation times.
- JSON exports with generic `records` collections now use supported `record_type` values and `recorded_at`, while still enforcing the manifest capture cutoff.
- OCR resource extraction rejects labels such as `analytics_warehouse` that lack a numeric resource suffix.
- Image category parsing now uses row context and the longest recognized typed resource prefix. This corrected policy handling for account profiles, support messages, analytics profiles, backups, exports, and security audit records. The change also avoids treating retained security logs or backup archives as search-index records to delete.
- Five manifest entries produced no evidence record or trace event in the catalog: `evidence_18`, `evidence_27`, `evidence_42`, `evidence_60`, and `evidence_90`. Their contents and cutoff-visible links were reviewed. They did not establish a supported fix for the 142 missing predictions: linked items concerned already-predicted cases, were not linked to a request, were after the relevant cutoff, or contained schema without data rows. This is not a claim that every artifact's contents have been converted into a structured record.
- The remaining 142 audit errors comprise 129 cases without cutoff-valid account presence/absence evidence and 13 without cutoff-valid linked evidence. The output status schema has no unresolved value; the run fails closed and withholds `output.csv` rather than inventing statuses, findings, or verification steps.

## Current verification

- Unit tests: **53 passed, 0 failed**. PyMuPDF emitted its existing `fitz` deprecation warning.
- Full pipeline: **376/518 predictions**, 142 audit errors (129 missing account state; 13 without cutoff-valid linked evidence), and 1 coverage validation error. Root `output.csv` was not written.
- Predicted-row status distribution: 45 `COMPLETE`, 323 `INCOMPLETE`, 8 `NOT_APPLICABLE`. These counts exclude the 142 cases that raised audit errors.
- Sample diagnostic: **23/32 predictions**, 9 audit errors, 14 differences, and 1 coverage validation error.
- Hidden-answer accuracy: **unavailable**; the supplied evaluation entry point is empty.
