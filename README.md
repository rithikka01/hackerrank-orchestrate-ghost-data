# HackerRank Orchestrate — October 2026

## Ghost Data Still Exists

### Overview

This project addresses the challenge of auditing customer data deletion workflows to determine whether personal data has actually been deleted across relevant systems.

A deletion workflow may report **Complete** while personal data remains in databases, logs, support attachments, exports, search indexes, archives, or backups. Synchronization and restoration processes may also cause previously deleted data to reappear.

The goal is to build an AI agent that evaluates deletion requests using available evidence and determines the appropriate deletion status and required remediation or verification steps.

### Problem Statement

For each deletion request, the agent must determine whether deletion was authorized and assess the available evidence to establish whether the deletion is complete.

The agent must return one of the following statuses:

- `COMPLETE` — deletion is supported by sufficient evidence.
- `INCOMPLETE` — remaining data or recreation risks require remediation or verification.
- `NOT_APPLICABLE` — deletion was not authorized or does not apply.

The output must include the ordered steps required to address outstanding findings and verify deletion where necessary.

### Project Structure

```text
hackerrank-orchestrate-october26-main/
├── code/                    # Agent implementation and tests
├── dataset/                 # Challenge requests and evidence
├── agent-trace/             # Agent execution traces
├── README.md                 # Project documentation
├── AGENTS.md                 # Agent instructions
├── CLAUDE.md                 # Additional instructions
├── problem_statement.md      # Challenge requirements
├── agent_trace_instructions.md
├── output.csv                # Generated predictions
├── code.zip                  # Code archive
├── agent-trace.zip           # Trace archive
└── log.txt                   # Execution log
```

### Technologies

- Python
- AI agent workflows
- CSV data processing
- Evidence-based auditing
- Automated testing and validation
- Git and GitHub

### Output Format

The output file is `output.csv`, with the following columns:

```csv
case_id,deletion_status,steps_json
```

Each row represents a deletion request and its predicted status and structured action steps.

### Running the Project

1. Clone the repository.
2. Open the project directory.
3. Install the dependencies listed in the project's requirements file.
4. Follow the execution instructions in `README.md`, `AGENTS.md`, and the relevant code documentation.
5. Run the agent against the supplied deletion requests.
6. Validate the generated `output.csv` against the challenge requirements.

### Testing and Evaluation

The project includes code, tests, datasets, and execution records to support implementation and evaluation.

**Evaluation note:** The generated output requires further evidence-based validation. The presence of an output file does not, by itself, establish that every deletion prediction is correct.

### Objective

The objective is to improve the reliability of deletion workflows by identifying residual personal data, documenting evidence-backed findings, recommending remediation, and requiring verification before declaring deletion complete.

---

*Developed as part of the HackerRank Orchestrate October 2026 challenge.*
