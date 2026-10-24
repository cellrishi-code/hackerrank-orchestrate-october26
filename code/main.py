#!/usr/bin/env python3
"""Generate the root-level output.csv for Ghost Data Still Exists."""
from __future__ import annotations
import argparse, csv, json, re, sys, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from audit_engine import DATA, ROOT, EvidenceIndex, aliases_for, build_users, deletion_requested, dt, load_csv, resolve_user

FIELDS = ["case_id", "deletion_status", "steps_json"]
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {"REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
            "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
            "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
            "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5}
OPS = {
"REPORT_REMAINING_RECORD": ("FINDING","PRESENT"), "REPORT_EXPOSED_PII": ("FINDING","PRESENT"),
"REPORT_ACTIVE_DATA_FLOW": ("FINDING","ACTIVE"), "REPORT_RESTORE_RISK": ("FINDING","ACTIVE"),
"DISABLE_DATA_FLOW": ("REMEDIATION","DISABLED"), "BLOCK_RESTORE": ("REMEDIATION","BLOCKED"),
"DELETE_RECORD": ("REMEDIATION","ABSENT"), "REDACT_RECORD": ("REMEDIATION","REDACTED"),
"ANONYMIZE_RECORD": ("REMEDIATION","ANONYMIZED"), "VERIFY_RECORD_ABSENT": ("VERIFICATION","ABSENT"),
"VERIFY_RECORD_PRESENT": ("VERIFICATION","PRESENT"), "VERIFY_RECORD_REDACTED": ("VERIFICATION","REDACTED"),
"VERIFY_RECORD_ANONYMIZED": ("VERIFICATION","ANONYMIZED"), "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION","DISABLED"),
"VERIFY_RESTORE_BLOCKED": ("VERIFICATION","BLOCKED")}

def make_step(op, system, rid, eid=""):
    phase, state = OPS[op]
    if phase == "REMEDIATION" and eid:
        raise ValueError("Proposed remediation cannot cite future evidence")
    return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": rid,
            "operation": op, "state": state, "evidence_id": eid}

def is_direct_match(keys, aliases):
    # Shared support conversations should retain context but must not retain the subject's direct identifiers.
    return bool({k for k in keys if k.startswith(("E:","P:","N:","H:"))} & aliases)

def build_plan(observations, aliases):
    issues, verified = [], []
    delete_categories = {"USER_PROFILE","SECONDARY_IDENTIFIER","SEARCH_INDEX_ENTRY","CACHE_ENTRY","SUPPORT_ATTACHMENT","USER_EXPORT","MARKETING_PROFILE"}
    redact_categories = {"SUPPORT_MESSAGE","EMAIL_DELIVERY_LOG","ACCOUNT_TOMBSTONE"}
    anon_categories = {"ANALYTICS_PROFILE","PRODUCT_TELEMETRY"}
    retain_categories = {"SECURITY_AUDIT_LOG","LEGAL_HOLD_RECORD"}
    for obs in observations:
        cat, state = obs["cat"], obs["state"]
        if state == "ABSENT":
            verified.append((obs, "VERIFY_RECORD_ABSENT"))
            continue
        if cat == "DATA_FLOW":
            if state == "ACTIVE": issues.append((obs, "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW"))
            elif state == "DISABLED": verified.append((obs, "VERIFY_DATA_FLOW_DISABLED"))
            continue
        if cat == "BACKUP_ARCHIVE":
            if state == "ACTIVE": issues.append((obs, "REPORT_RESTORE_RISK", "BLOCK_RESTORE"))
            elif state == "BLOCKED": verified.append((obs, "VERIFY_RESTORE_BLOCKED"))
            else: verified.append((obs, "VERIFY_RECORD_PRESENT"))
            continue
        if cat in retain_categories:
            verified.append((obs, "VERIFY_RECORD_PRESENT"))
            continue
        if cat == "ACCOUNT_TOMBSTONE":
            if state == "REDACTED": verified.append((obs, "VERIFY_RECORD_REDACTED"))
            else: issues.append((obs, "REPORT_EXPOSED_PII", "REDACT_RECORD"))
            continue
        direct = bool(obs["keys"] & aliases)
        if cat in delete_categories:
            issues.append((obs, "REPORT_REMAINING_RECORD", "DELETE_RECORD"))
        elif cat in redact_categories:
            # Match a direct identifier, not only the permitted stable internal user reference.
            if is_direct_match(obs["keys"], aliases):
                issues.append((obs, "REPORT_EXPOSED_PII", "REDACT_RECORD"))
            elif state == "REDACTED":
                verified.append((obs, "VERIFY_RECORD_REDACTED"))
        elif cat in anon_categories:
            if direct: issues.append((obs, "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD"))
            else: verified.append((obs, "VERIFY_RECORD_ANONYMIZED"))

    account_absent = [o for o in observations if o["cat"] == "USER_PROFILE" and o["system"] == "account_service" and o["state"] == "ABSENT"]
    if account_absent and not issues:
        checks = {(o["system"], o["rid"], op): (o, op) for o, op in verified}
        ordered = sorted(checks.values(), key=lambda x: (OP_ORDER[x[1]], x[0]["system"], x[0]["rid"]))
        output = [make_step(op, o["system"], o["rid"], o["eid"]) for o, op in ordered]
        if output:
            for i, item in enumerate(output, 1): item["step_no"] = i
            return "COMPLETE", output

    findings = sorted([(o, f) for o, f, _ in issues], key=lambda x: (OP_ORDER[x[1]], x[0]["system"], x[0]["rid"]))
    remedies = sorted([(o, r) for o, _, r in issues], key=lambda x: (OP_ORDER[x[1]], x[0]["system"], x[0]["rid"]))
    output = [make_step(op, o["system"], o["rid"], o["eid"]) for o, op in findings]
    output.extend(make_step(op, o["system"], o["rid"]) for o, op in remedies)
    # Explicitly keep the baseline account state and required retained/known-compliant resources in the plan.
    for o in account_absent: output.append(make_step("VERIFY_RECORD_ABSENT", o["system"], o["rid"]))
    for o, op in verified:
        if op != "VERIFY_RECORD_ABSENT": output.append(make_step(op, o["system"], o["rid"]))
    future_op = {"DELETE_RECORD":"VERIFY_RECORD_ABSENT", "REDACT_RECORD":"VERIFY_RECORD_REDACTED",
                 "ANONYMIZE_RECORD":"VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW":"VERIFY_DATA_FLOW_DISABLED",
                 "BLOCK_RESTORE":"VERIFY_RESTORE_BLOCKED"}
    for o, _, remedy in issues: output.append(make_step(future_op[remedy], o["system"], o["rid"]))
    unique = {}
    for item in output:
        unique.setdefault((item["phase"], item["system_id"], item["resource_id"], item["operation"]), item)
    output = list(unique.values())
    output.sort(key=lambda s: (PHASE_ORDER[s["phase"]], OP_ORDER[s["operation"]], s["system_id"], s["resource_id"]))
    for i, item in enumerate(output, 1): item["step_no"] = i
    return "INCOMPLETE", output

def validate_output(rows, expected_ids, valid_evidence):
    errors = []
    ids = [r["case_id"] for r in rows]
    if len(rows) != len(expected_ids): errors.append(f"row count {len(rows)} != {len(expected_ids)}")
    if ids != sorted(expected_ids): errors.append("case IDs missing, duplicated, or unsorted")
    for row in rows:
        if row["deletion_status"] not in {"COMPLETE","INCOMPLETE","NOT_APPLICABLE"}:
            errors.append(f"{row['case_id']}: invalid status")
        try: steps = json.loads(row["steps_json"])
        except json.JSONDecodeError: errors.append(f"{row['case_id']}: invalid JSON"); continue
        if not isinstance(steps, list): errors.append(f"{row['case_id']}: JSON must be an array"); continue
        if row["deletion_status"] == "NOT_APPLICABLE" and steps: errors.append(f"{row['case_id']}: expected []")
        if [s.get("step_no") for s in steps] != list(range(1, len(steps)+1)): errors.append(f"{row['case_id']}: invalid step numbers")
        if [s.get("phase") for s in steps] != sorted([s.get("phase") for s in steps], key=lambda p: PHASE_ORDER.get(p, 99)):
            errors.append(f"{row['case_id']}: invalid phase ordering")
        for s in steps:
            required = {"step_no","phase","system_id","resource_id","operation","state","evidence_id"}
            if set(s) != required: errors.append(f"{row['case_id']}: wrong fields")
            if OPS.get(s.get("operation")) != (s.get("phase"), s.get("state")): errors.append(f"{row['case_id']}: operation/state mismatch")
            eid = s.get("evidence_id","")
            if eid and eid not in valid_evidence and not re.fullmatch(r"(?:activity|audit)_\d+", eid):
                errors.append(f"{row['case_id']}: unknown evidence {eid}")
            if s.get("phase") == "FINDING" and not eid: errors.append(f"{row['case_id']}: finding without evidence")
            if row["deletion_status"] == "COMPLETE" and s.get("phase") == "VERIFICATION" and not eid:
                errors.append(f"{row['case_id']}: complete verification without evidence")
            if row["deletion_status"] == "INCOMPLETE" and s.get("phase") == "REMEDIATION" and eid:
                errors.append(f"{row['case_id']}: remediation cites evidence")
    if errors: raise ValueError("Output validation failed:\n" + "\n".join(errors[:25]))
    return {"cases":len(rows), "steps":sum(len(json.loads(r["steps_json"])) for r in rows)}

def run(input_path=None, output_path=None):
    started = time.perf_counter()
    input_path = Path(input_path or DATA/"deletion_requests.csv")
    output_path = Path(output_path or ROOT/"output.csv")
    requests = load_csv(input_path)
    if not requests: raise ValueError(f"No requests in {input_path}")
    identities = load_csv(DATA/"user_identities.csv")
    audit = load_csv(DATA/"user_audit_log.csv")
    users, email_index = build_users(identities, audit)
    evidence = EvidenceIndex()
    out, unmatched = [], 0
    for request in requests:
        cutoff = dt(request.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
        if not deletion_requested(request.get("request_text","")):
            out.append({"case_id":request["case_id"],"deletion_status":"NOT_APPLICABLE","steps_json":"[]"})
            continue
        email = request.get("email","")
        uid = resolve_user(email, dt(request.get("requested_at")), users, email_index, audit)
        aliases = aliases_for(uid or "", users.get(uid or ""), audit, cutoff, email)
        observations = evidence.for_user(aliases, cutoff)
        # If email history is ambiguous, evidence may uniquely bind it to one stable user_id.
        if not uid and observations:
            refs = {k[2:] for obs in observations for k in obs["keys"] if k.startswith("U:")}
            if len(refs) == 1:
                uid = next(iter(refs))
                aliases = aliases_for(uid, users.get(uid), audit, cutoff, email)
                observations = evidence.for_user(aliases, cutoff)
        if not observations:
            unmatched += 1
            status, steps = "INCOMPLETE", []
        else:
            status, steps = build_plan(observations, aliases)
        out.append({"case_id":request["case_id"], "deletion_status":status,
                    "steps_json":json.dumps(steps, ensure_ascii=False, separators=(",",":"), sort_keys=True)})
    out.sort(key=lambda r:r["case_id"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader(); writer.writerows(out)
    valid = {r["file_id"] for r in evidence.manifest}
    validation = validate_output(out, [r["case_id"] for r in requests], valid)
    counts = dict(Counter(r["deletion_status"] for r in out))
    return {"output":str(output_path), "input_rows":len(requests), "output_rows":len(out), "status_counts":counts,
            "unmatched_cases":unmatched, "evidence_files":len(evidence.manifest), "indexed_observations":len(evidence.observations),
            "identifier_index_keys":len(evidence.index), "evidence_manifest_sha256":evidence.fingerprint, "steps":validation["steps"], "elapsed_seconds":round(time.perf_counter()-started,3)}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,default=DATA/"deletion_requests.csv")
    parser.add_argument("--output",type=Path,default=ROOT/"output.csv")
    args=parser.parse_args()
    try: print(json.dumps(run(args.input,args.output),indent=2,sort_keys=True)); return 0
    except Exception as exc: print(f"ERROR: {type(exc).__name__}: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
