# Usage and token report

## Latest full-dataset run

Command: `.\.venv\Scripts\python.exe code\main.py` from the repository root. The run loaded all 518 requests, returned 376 predictions, and stopped with 142 audit errors and one coverage validation error. Root `output.csv` was not written, so this was an attempted run, not a qualifying completed submission run.

The errors were 129 cases without cutoff-valid account presence/absence evidence and 13 cases without cutoff-valid linked evidence. The predicted-row status distribution was 45 `COMPLETE`, 323 `INCOMPLETE`, and 8 `NOT_APPLICABLE`.

## Model and usage accounting

The solution uses deterministic Python rules and local OCR. No hosted language model, API, prompt, or provider account is called by the solution.

| Component | Provider / model | Run usage | Tokens | Cost |
|---|---|---:|---:|---:|
| Language model | None used | 0 calls | 0 input, 0 output, 0 total | $0.00 provider charges |
| OCR | Local `rapidocr_onnxruntime` 1.2.3 using ONNX Runtime; package components are PP-OCRv3 detector and recognizer plus PP-OCRv2 angle classifier | 11 RapidOCR wrapper calls, one per manifest image; internal component call counts are not exposed | Not applicable; OCR usage is not token-based and the wrapper exposes no token counter | No hosted provider charge; local compute cost not measured |

Language-model tokens total **0**; average **0.0 tokens per request** across 518 requests. These values describe the absence of language-model calls. OCR token counts are not available or applicable. The measured external model/API cost is **$0.00 overall** and **$0.00 per request**. No estimate is available for local CPU, electricity, or machine cost, so those costs are not represented as zero.

## Submission status

This run did not produce a validated 518-row `output.csv`. The report records the failed full-run attempt and must not be presented as evidence that the output requirement passed. No provider usage dashboard or local-compute billing meter was available; the distinctions above are based on the program's actual call path and the installed local OCR package.
