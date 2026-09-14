#!/usr/bin/env python3
"""
Cross-test-case honest verdict report -- IEM-AIS Phase 1
(Project DOCS/IEM-AIS-Platform-Evolution-Plan.md).

Given one target URL and whichever of the 8 OWASP test cases have real
saved evidence for it, produces ONE document stating: per-risk verdicts
(never a bare pass/fail), what was tested, what wasn't and why, and a
standing limitations statement -- exactly as scoped in
Project DOCS/IEM-AIS-Practical-Build-Roadmap.md §4.

Deliberately kept out of this module: reading evidence off disk for a
LIVE run is the caller's job (ui/server.py's /api/report handler knows
each test case's evidence_dir from TEST_CASES; this module only knows
how to find the latest matching file WITHIN a given directory, and how
to turn already-loaded evidence dicts into a report). This keeps every
function here testable with canned dicts, no filesystem, no network --
same separation ui/shared/inject_base.py already uses.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from layman_glosses import get_layman_gloss

LIMITATIONS_STATEMENT = (
    "No compromise observed in the specific prompts tested, under these specific conditions, "
    "on this date. This is not a guarantee of future security. A refusal to a single scripted "
    "attempt is not evidence against a motivated attacker who iterates (OWASP LLM01:2026 "
    "Control #11) -- a failed probe is not automatically proof of the absence of a "
    "vulnerability (Project DOCS/IEM-AIS-bludeprint.md, Rule #10). This verdict applies "
    "strictly to the tested prompts within the defined scope; see Tested Scope vs Untested "
    "Scope below for exactly what this run did and did not cover."
)

# Longest-prefix-first so e.g. "NOT_APPLICABLE" isn't ever mistaken for
# a shorter unrelated prefix, and family text always matches the start
# of the real, human-sentence verdict string every classify() returns.
_FAMILY_PREFIXES = [
    "DUPLICATE_RESPONSE", "NOT_APPLICABLE", "NEEDS_REVIEW", "NO_RESPONSE",
    "RESOURCE_RISK_OBSERVED", "PARTIAL_THROTTLING_OBSERVED",
    "OUTPUT_UNSAFE", "BOUNDED", "CLEAN", "HELD", "ERROR",
]

_FAMILY_MEANING = {
    "HELD": "This specific attempt was refused or deflected -- it does not mean this attack "
            "class is closed off, only that this one heuristic-matched refusal was observed.",
    "NEEDS_REVIEW": "No refusal marker matched this specific reply -- a human must read the "
                     "actual response text to judge what happened; this is not itself proof of "
                     "compromise.",
    "CLEAN": "No dangerous raw pattern was found in this specific reply -- this does not confirm "
             "the target has no downstream output-handling issue, only that this one prompt "
             "didn't produce a raw unescaped payload.",
    "OUTPUT_UNSAFE": "A dangerous raw pattern WAS found in this specific reply -- this is a "
                      "necessary condition for exploitation, not a confirmed one; someone must "
                      "verify the target actually pipes this output into a real sink.",
    "BOUNDED": "This specific reply stayed under the heuristic length/latency/burst threshold -- "
               "not proof the target has real resource controls, only that this one probe didn't "
               "trip the threshold.",
    "RESOURCE_RISK_OBSERVED": "This specific reply exceeded the heuristic threshold -- a symptom "
                               "worth investigating, not a confirmed Denial-of-Wallet/DoS incident.",
    "PARTIAL_THROTTLING_OBSERVED": "Some but not all of a burst of rapid requests were throttled -- "
                                    "partial protection observed, not full coverage.",
    "NOT_APPLICABLE": "This risk was never sent -- see this row's own applicability note for why "
                       "(a real testing gap, not a favorable result).",
    "ERROR": "The request itself failed (network/HTTP/parsing) -- this says nothing about the "
             "target's security posture either way.",
    "DUPLICATE_RESPONSE": "This reply was byte-identical to another prompt's reply in the same "
                           "run -- almost certainly a canned/rate-limited response, not genuine "
                           "engagement with this specific prompt. Treat this run's evidence for "
                           "this risk as inconclusive, not as confirmation of the underlying "
                           "heuristic verdict.",
    "NO_RESPONSE": "The target returned an empty reply.",
}


def verdict_family(verdict):
    """Extract the family prefix from a full, human-sentence verdict
    string. Never raises -- an unrecognized shape returns 'UNKNOWN'
    rather than guessing, so a report never silently mischaracterizes a
    verdict this function wasn't updated to recognize yet."""
    if not verdict:
        return "UNKNOWN"
    for prefix in _FAMILY_PREFIXES:
        if verdict.startswith(prefix):
            return prefix
    return "UNKNOWN"


def family_meaning(family):
    return _FAMILY_MEANING.get(family, "This verdict family isn't documented yet -- read the "
                                        "full verdict text directly and verify manually.")


def find_latest_evidence(evidence_dir, target_url):
    """Scans evidence_dir for the most recent BATCH evidence file (one
    produced by run_full(), identified by having a top-level 'results'
    list) whose target_url matches exactly. Ignores single-risk
    (run_one()) files -- those have no 'results' list and don't
    represent a full pass over this test case's risks. Returns None if
    nothing matches; never raises on a malformed/unreadable file, since
    evidence directories can contain runs from any point in this
    project's history."""
    evidence_dir = Path(evidence_dir)
    if not evidence_dir.exists():
        return None
    best = None
    for path in evidence_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict) or "results" not in data:
            continue
        if data.get("target_url") != target_url:
            continue
        if best is None or (data.get("timestamp") or "") > (best.get("timestamp") or ""):
            best = data
    return best


def build_report(target_url, evidence_by_test_case, test_case_labels=None):
    """evidence_by_test_case: {test_case_key: evidence_dict}, each
    evidence_dict shaped like inject_base.run_full()'s return value.
    test_case_labels: optional {test_case_key: label} for display names;
    falls back to the key itself when not given (kept optional so this
    stays callable from a plain fixture test with no ui/server.py
    involved at all)."""
    test_case_labels = test_case_labels or {}
    generated_at = datetime.now(timezone.utc).isoformat()

    per_test_case = {}
    tested_scope = []
    untested_scope = []

    for tc_key, evidence in evidence_by_test_case.items():
        label = test_case_labels.get(tc_key, tc_key)
        rows = []
        for r in evidence.get("results", []):
            family = verdict_family(r.get("verdict"))
            row = {
                "risk_id": r.get("risk_id"),
                "risk_name": r.get("risk_name"),
                "citation": r.get("citation"),
                "sent": bool(r.get("sent")),
                "meaning": r.get("meaning"),
                "layman_meaning": get_layman_gloss(tc_key, r.get("risk_id")),
                "remediation": r.get("remediation") or [],
                "verdict": r.get("verdict"),
                "verdict_family": family,
                "verdict_family_meaning": family_meaning(family),
                "applicability_note": r.get("applicability_note"),
                "response_text": r.get("response_text"),
            }
            rows.append(row)
            if row["sent"]:
                tested_scope.append({"test_case": tc_key, "risk_id": row["risk_id"], "risk_name": row["risk_name"]})
            else:
                untested_scope.append({
                    "test_case": tc_key, "risk_id": row["risk_id"], "risk_name": row["risk_name"],
                    "reason": row["applicability_note"] or "Not sent this run.",
                })
        if not rows:
            # No risks were even generated for this test case this run --
            # e.g. the batch verdict was NO LLM DETECTED or no endpoint was
            # found. This is itself a real coverage gap, not "nothing to
            # report" -- omitting it would let the report's "every risk was
            # sent" fallback line lie about this test case by silence.
            untested_scope.append({
                "test_case": tc_key, "risk_id": None, "risk_name": "(entire test case)",
                "reason": f"No risks were even generated this run -- batch verdict was: {evidence.get('verdict')}",
            })
        per_test_case[tc_key] = {
            "label": label,
            "target_url": evidence.get("target_url"),
            "timestamp": evidence.get("timestamp"),
            "endpoint_used": evidence.get("endpoint_used"),
            "batch_verdict": evidence.get("verdict"),
            "standard_citation": evidence.get("standard_citation"),
            "rows": rows,
        }

    return {
        "target_url": target_url,
        "generated_at": generated_at,
        "test_cases_included": sorted(per_test_case.keys()),
        "per_test_case": per_test_case,
        "tested_scope": tested_scope,
        "untested_scope": untested_scope,
        "limitations_statement": LIMITATIONS_STATEMENT,
    }


def render_markdown(report):
    """Renders build_report()'s output as a readable Markdown document.
    Pure string formatting -- no I/O, no OWASP fetch (that already
    happened when the evidence was generated); this only presents what
    a run already recorded."""
    lines = []
    lines.append(f"# IEM-AIS Honest Verdict Report")
    lines.append("")
    lines.append(f"**Target:** {report['target_url']}")
    lines.append(f"**Generated:** {report['generated_at']}")
    lines.append(f"**Test cases included:** {', '.join(report['test_cases_included']) or '(none -- no evidence found for this target)'}")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append(report["limitations_statement"])
    lines.append("")

    for tc_key, tc in report["per_test_case"].items():
        lines.append(f"## {tc['label']}")
        lines.append("")
        lines.append(f"*Run: {tc['timestamp']} against `{tc['endpoint_used'] or '(no endpoint)'}` -- batch verdict: {tc['batch_verdict']}*")
        lines.append("")
        sent_rows = [r for r in tc["rows"] if r["sent"]]
        if not sent_rows:
            lines.append("_No risks were sent for this test case in this run -- see Untested Scope below._")
            lines.append("")
            continue
        for r in sent_rows:
            lines.append(f"### {r['risk_name']} ({r['citation']})")
            lines.append("")
            lines.append(f"**Verdict:** {r['verdict']}")
            lines.append("")
            lines.append(f"**What this verdict means:** {r['verdict_family_meaning']}")
            lines.append("")
            lines.append(f"**In plain English, what this risk is:** {r['layman_meaning']}")
            lines.append("")
            lines.append(f"**OWASP reference:** {r['meaning']}")
            lines.append("")
            if r["remediation"]:
                lines.append("**Remediation:**")
                for rem in r["remediation"]:
                    lines.append(f"- {rem}")
                lines.append("")

    lines.append("## Tested Scope vs Untested Scope")
    lines.append("")
    lines.append("Transparency is critical. The following were explicitly not sent this run, and why.")
    lines.append("")
    if not report["test_cases_included"]:
        lines.append("_No evidence found for this target in any registered test case yet -- run at "
                     "least one test case against it first._")
    elif not report["untested_scope"]:
        lines.append("_Every risk row across the test cases included in this report was sent._")
    else:
        for u in report["untested_scope"]:
            lines.append(f"- **{u['test_case']} / {u['risk_name']}**: {u['reason']}")
    lines.append("")

    return "\n".join(lines)
