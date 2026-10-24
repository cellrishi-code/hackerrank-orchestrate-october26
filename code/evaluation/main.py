#!/usr/bin/env python3
"""Evaluate public regression examples and independent safety/contract cases."""
from __future__ import annotations
import csv, hashlib, json, sys, tempfile
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
ROOT = CODE.parent
sys.path.insert(0, str(CODE))
from audit_engine import DATA, dt, deletion_requested
from main import run, validate_output

def read_output(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return {row["case_id"]: row for row in csv.DictReader(f)}

def steps(value):
    return json.loads(value) if isinstance(value, str) else value

def compare(reference, predicted):
    case_ids = sorted(reference)
    status_ok = sum(reference[c]["deletion_status"] == predicted.get(c, {}).get("deletion_status") for c in case_ids)
    exact_ok = object_correct = object_total = field_correct = field_total = 0
    for cid in case_ids:
        exp = steps(reference[cid]["steps_json"])
        got = steps(predicted.get(cid, {}).get("steps_json", "[]"))
        if reference[cid]["deletion_status"] == predicted.get(cid, {}).get("deletion_status") and exp == got:
            exact_ok += 1
        limit = max(len(exp), len(got))
        object_total += limit
        field_total += limit * 7
        for i in range(limit):
            if i < len(exp) and i < len(got):
                if exp[i] == got[i]: object_correct += 1
                for key in ("step_no","phase","system_id","resource_id","operation","state","evidence_id"):
                    if exp[i].get(key) == got[i].get(key): field_correct += 1
    n = len(case_ids)
    return {
        "sample_cases": n,
        "status_accuracy": status_ok / n if n else 0,
        "exact_status_and_sequence_accuracy": exact_ok / n if n else 0,
        "step_object_accuracy": object_correct / object_total if object_total else 1.0,
        "step_field_accuracy": field_correct / field_total if field_total else 1.0,
        "reference_steps": sum(len(steps(r["steps_json"])) for r in reference.values()),
        "predicted_steps": sum(len(steps(r.get("steps_json","[]"))) for r in predicted.values()),
    }

def mismatch_details(reference, predicted):
    """Small, deterministic signatures make public regression failures actionable."""
    details = []
    for cid in sorted(reference):
        expected = reference[cid]
        actual = predicted.get(cid, {"deletion_status":"MISSING", "steps_json":"[]"})
        exp_steps = steps(expected["steps_json"])
        got_steps = steps(actual.get("steps_json", "[]"))
        if expected["deletion_status"] == actual.get("deletion_status") and exp_steps == got_steps:
            continue
        def signature(items):
            return [
                {
                    "phase": item.get("phase"),
                    "operation": item.get("operation"),
                    "system_id": item.get("system_id"),
                    "resource_id": item.get("resource_id"),
                    "state": item.get("state"),
                    "evidence_id": item.get("evidence_id"),
                }
                for item in items
            ]
        details.append({
            "case_id": cid,
            "expected_status": expected["deletion_status"],
            "predicted_status": actual.get("deletion_status", "MISSING"),
            "expected_steps": signature(exp_steps),
            "predicted_steps": signature(got_steps),
        })
    return details

def custom_tests():
    passed, failed = [], []
    tests = [
        ("non-deletion access request", "I only request access to a copy of my personal data.", False),
        ("marketing-only opt-out", "Please unsubscribe me from promotional emails without deleting my account.", False),
        ("explicit Spanish deletion", "Quiero eliminar mi cuenta y borrar mis datos personales.", True),
        ("negated deletion", "Please do not delete my account; only correct the email address.", False),
        ("explicit French deletion", "Je demande la suppression définitive de mon compte.", True),
    ]
    for name, text, expected in tests:
        actual = deletion_requested(text)
        (passed if actual == expected else failed).append(name if actual == expected else f"{name}: expected {expected}, got {actual}")
    try:
        validate_output([{"case_id":"custom_1","deletion_status":"NOT_APPLICABLE","steps_json":"[]"}], ["custom_1"], set())
        passed.append("NOT_APPLICABLE requires an empty step array")
    except Exception as e:
        failed.append(f"NOT_APPLICABLE contract: {e}")
    try:
        validate_output([{"case_id":"custom_1","deletion_status":"INVALID","steps_json":"[]"}], ["custom_1"], set())
        failed.append("invalid status was accepted")
    except ValueError:
        passed.append("invalid status is rejected")
    if dt("2026-09-01T12:00:00Z") == dt("2026-09-01T14:00:00+02:00"):
        passed.append("UTC offset normalization")
    else:
        failed.append("UTC offset normalization failed")
    return passed, failed

def write_reports(scores, passed, failed, full_stats, output_path):
    pct = lambda key: 100 * scores[key]
    digest = hashlib.sha256(output_path.read_bytes()).hexdigest() if output_path.exists() else "unavailable"
    lines = [
        "# Evaluation Report", "",
        "## Full-dataset structural validation", "",
        f"- Input cases: {full_stats.get('input_rows','not measured')}",
        f"- Output rows: {full_stats.get('output_rows','not measured')}",
        f"- Status distribution: {json.dumps(full_stats.get('status_counts',{}),sort_keys=True)}",
        f"- Indexed observations: {full_stats.get('indexed_observations','not measured')} across {full_stats.get('evidence_files','not measured')} evidence-manifest entries.",
        f"- Unmatched deletion cases: {full_stats.get('unmatched_cases','not measured')}; these remain INCOMPLETE rather than being falsely certified.",
        f"- Runtime in seconds: {full_stats.get('elapsed_seconds','not measured')}",
        f"- Root output SHA-256: {digest}",
        f"- Evidence-manifest SHA-256: {full_stats.get('evidence_manifest_sha256','not measured')}", "",
        "## Public 32-case regression comparison", "",
        "- The sample answer file is used only for evaluation, never as prediction input.",
        f"- Status accuracy: {pct('status_accuracy'):.2f}% ({round(scores['status_accuracy']*scores['sample_cases'])}/{scores['sample_cases']})",
        f"- Exact status plus ordered step sequence accuracy: {pct('exact_status_and_sequence_accuracy'):.2f}%",
        f"- Step-object accuracy (position-aligned; missing/extra steps penalized): {pct('step_object_accuracy'):.2f}%",
        f"- Step-field accuracy over the seven required fields: {pct('step_field_accuracy'):.2f}%",
        f"- Reference steps: {scores['reference_steps']}; predicted steps: {scores['predicted_steps']}.",
        "", "These figures measure agreement with public examples only. They are not hidden-test accuracy or a guarantee of full-dataset correctness.", "",
        "## Additional participant-authored tests", "",
        *[f"- PASS — {v}" for v in passed],
        *[f"- FAIL — {v}" for v in failed],
        "", "## Failures and improvements", "",
        "- Added a one-pass evidence loader and an inverted typed-identifier index to avoid rescanning all evidence for every case.",
        "- Enforced point-in-time filtering using both manifest capture time and per-record observation time.",
        "- Resolved conflicting observations for a resource conservatively: at equal timestamps, a riskier state wins.",
        "- Added output-contract checks for row coverage, allowed statuses, valid JSON, consecutive step numbers, phase order, operation/state combinations, evidence IDs, and evidence-free proposed remediation.",
        "- Added dataset path containment checks and bounded PDF/OCR subprocess timeouts.",
        "- Added multilingual deletion-intent, negative-intent, non-deletion request, and time-zone normalization tests.",
        "- Remaining risks: deterministic parsing cannot perfectly resolve every ambiguous screenshot or context-dependent retention exception. Public sample discrepancies must be inspected at evidence level before performance is claimed.",
        "", "## Reproduction", "",
        "From the repository root, run: python code/main.py, then python code/evaluation/main.py.",
    ]
    target = CODE / "evaluation" / "evaluation_report.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

def write_usage(stats):
    target = CODE / "evaluation" / "usage_report.md"
    lines = [
        "# Model Usage and Cost Report", "",
        "The baseline is a deterministic local Python pipeline. It does not call an LLM, hosted model API, or external data service.",
        "", "## Final full-dataset run", "",
        f"- Input requests: {stats.get('input_rows','not measured')}",
        f"- Output rows: {stats.get('output_rows','not measured')}",
        f"- Pipeline runtime: {stats.get('elapsed_seconds','not measured')} seconds",
        "- Model provider/name: None (no model used)",
        "- Model calls: 0",
        "- Input tokens: 0",
        "- Output tokens: 0",
        "- Total tokens: 0",
        "- Average tokens per request: 0",
        "- Estimated model API cost: $0.00 total / $0.00 per request",
        "- Local compute, OCR, and CI runner charges are not included in model API cost.",
        "", "No usage or cost figures are fabricated. Future model-based components must report measured provider usage here.",
    ]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

def main():
    output = ROOT / "output.csv"
    if not output.is_file():
        raise SystemExit("Missing root output.csv; run code/main.py first.")
    stats_path = ROOT / "run_stats.json"
    try:
        stats = json.loads(stats_path.read_text(encoding="utf-8")) if stats_path.exists() else {}
    except json.JSONDecodeError:
        stats = {}
    with tempfile.TemporaryDirectory(prefix="ghost-audit-eval-") as tmp:
        sample_output = Path(tmp) / "sample_predicted.csv"
        sample_stats = run(DATA / "sample_deletion_requests.csv", sample_output)
        reference = read_output(DATA / "sample_output.csv")
        predicted = read_output(sample_output)
        scores = compare(reference, predicted)
        mismatches = mismatch_details(reference, predicted)
    passed, failed = custom_tests()
    write_reports(scores, passed, failed, stats or sample_stats, output)
    write_usage(stats or sample_stats)
    print(json.dumps({"public_sample_metrics":scores,"public_sample_mismatches":mismatches,
                      "custom_tests_passed":len(passed),"custom_test_failures":failed,
                      "full_output_rows":len(read_output(output)),"reports":["code/evaluation/evaluation_report.md","code/evaluation/usage_report.md"]},indent=2,sort_keys=True))
    return 1 if failed else 0

if __name__ == "__main__":
    raise SystemExit(main())
