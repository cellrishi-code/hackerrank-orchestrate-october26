# Ghost Data Still Exists — Deletion Audit Agent

This directory contains the runnable submission implementation.

## Requirements

- Python 3.11 or newer
- The challenge's participant-facing dataset directory at the repository root
- pypdf for PDF text extraction
- Optional on Linux: tesseract-ocr and poppler-utils for image/PDF evidence extraction

Install dependencies from the repository root:

    python -m pip install -r code/requirements.txt

Run the complete 518-request dataset:

    python code/main.py

The resulting output.csv is written at the repository root. The program prints a JSON run summary. Run the public regression comparison and additional contract tests after that:

    python code/evaluation/main.py

Create the submission archive (after running evaluation):

    python code/package.py

## Architecture

- audit_engine.py loads participant-visible evidence, applies temporal cutoffs, resolves current and historical identifiers, and builds a typed inverted index for fast lookup.
- main.py constructs evidence-backed findings, policy-aligned remediation plans, and verification steps; writes and validates the required CSV schema.
- evaluation/main.py compares predictions against the 32 public examples and runs independent intent, serialization, and timestamp tests.
- package.py creates code.zip with source and reports only.

Evidence is indexed once per invocation instead of repeatedly scanning all evidence for each request. Identifier keys are typed (email, phone, hash, stable user reference, name) to reduce accidental cross-user matches. Activity events supply resource linkage only; workflow claims are not treated as proof that deletion succeeded.

## Security and correctness controls

- Reads are local; the pipeline does not send the dataset to a model or external service.
- Evidence paths are resolved and checked to remain under the dataset directory.
- Evidence SQL is interpreted in an ephemeral in-memory SQLite database. File attachment, extension loading, and common file I/O SQL functions are denied.
- PDF and OCR subprocess calls have timeouts and are optional.
- Evidence captured after a case's audit_at is excluded; record observation times are also checked.
- Conflicting states at the same point in time are handled conservatively, favoring the state that risks leaving personal data exposed.
- The pipeline refuses to certify completion when it cannot find point-in-time account absence evidence.
- Output validation checks coverage, allowed statuses, valid JSON, required fields, step numbering, phase order, operation/state compatibility, and evidence references.

## Limitations

This baseline is deterministic rather than LLM-driven. It cannot perfectly interpret every screenshot, ambiguous identity match, legal hold, or retention exception. OCR availability affects image evidence extraction. Review public-sample mismatches listed in evaluation/evaluation_report.md rather than treating the run as guaranteed hidden-test success.

The challenge's provided sample answers are used only by the evaluation script. They are never loaded by the prediction pipeline.
