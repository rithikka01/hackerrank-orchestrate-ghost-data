# Usage and token report

## Latest full-dataset attempt

The latest attempted run loaded all 518 requests, produced 378 predictions, encountered 140 audit errors and one coverage validation error, then withheld root `output.csv`. It is **not** a qualifying final run that produced the required submission file. This report records the attempt accurately and must be updated if a later run produces a validated output.

## Model and usage accounting

The solution is deterministic local Python. Its declared dependencies are PyMuPDF and RapidOCR; source code contains no LLM provider client or model call. OCR runs locally and does not use language-model tokens.

| Item | Measured value |
|---|---:|
| Model provider | None used by the solution |
| Model name | None used by the solution |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request (518 requests) | 0.0 |
| Estimated model cost | $0.00 |
| Estimated model cost per request | $0.00 |

These are zeros because the audited program made no model calls, not estimates from a provider billing dashboard. No API credentials or external model services were used by the solution.

## Submission status

Because this attempt did not produce a valid 518-row `output.csv`, these usage values describe an attempted full-dataset execution, not a completed submission run. Do not present this report as evidence that the output requirement has passed. Update it only after a complete validated run, retaining zero model usage if the solution remains deterministic and local.
