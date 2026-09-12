#!/usr/bin/env python3
"""
Shared orchestration mechanics for every IEM-AIS test-case inject.py.

Filled in from the four existing inject.py files, which agreed almost
verbatim on everything except classify()'s shape (see CLAUDE.md: that
stays deliberately different per skill, so it's a callback here, never
implemented in this file).

What stays OUT of this file, on purpose:
  - classify()/classify_output()/classify_consumption() -- each skill's
    own inject.py keeps its classifier and passes it in as classify_fn.
  - REFUSAL_MARKERS / DANGEROUS_PATTERNS -- the risk-specific taxonomy
    data each classifier reads.
  - prompt_generator.py and everything in it (build_prompts,
    RISK_TO_CONTROLS, the live OWASP fetch) -- stays fully owned per-skill.

classify_fn contract every skill's classifier must satisfy going forward:
    classify_fn(risk_id, response_text, elapsed_ms=None, burst_stats=None) -> str
A skill that doesn't need elapsed_ms/burst_stats just ignores those kwargs.
"""

import json
import re
import time
import urllib.request
import urllib.error
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import site_analyzer  # shared, generic -- sibling module in ui/shared/

REPLY_FIELD_CANDIDATES = ["reply", "response", "message", "answer", "text", "output", "completion", "result"]
DEFAULT_TIMEOUT = 60


def _overrides_path(skill_dir):
    return Path(skill_dir) / "config" / "site_overrides.json"


def load_overrides(url, skill_dir):
    """Explicit, user-supplied field values ONLY. Nothing here is guessed
    or derived; an absent/unmatched entry just means no override exists."""
    path = _overrides_path(skill_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data.get(url, {})


def pick_endpoint(url, endpoints):
    """Prefer whichever endpoint's path shares the most word tokens with
    the URL being tested (e.g. /liftoff -> /api/liftoff-chat over a
    generic /api/chat). Falls back to the first endpoint on a tie."""
    if not endpoints:
        return None
    if len(endpoints) == 1:
        return endpoints[0]
    url_tokens = set(re.findall(r"[a-z0-9]+", urlparse(url).path.lower()))

    def score(ep):
        ep_tokens = set(re.findall(r"[a-z0-9]+", ep["path"].lower()))
        return len(url_tokens & ep_tokens)

    return max(endpoints, key=score)


def describe_config_needs(url, profile, skill_dir):
    """What's missing before results for THIS site are trustworthy --
    computed fresh per site, never templated from another target."""
    if not profile.get("is_llm_site") or not profile.get("endpoints"):
        return None

    endpoint = pick_endpoint(url, profile["endpoints"])
    existing = load_overrides(url, skill_dir)
    missing = [f for f in endpoint.get("extra_fields", []) if f not in existing]

    if not missing:
        return {"endpoint_used": endpoint["path"], "missing_fields": [], "config_snippet": None,
                "already_configured": bool(existing)}

    snippet = json.dumps({url: {f: "<fill in the real value for this field>" for f in missing}}, indent=2)
    return {
        "endpoint_used": endpoint["path"],
        "missing_fields": missing,
        "config_snippet": snippet,
        "config_path": str(_overrides_path(skill_dir)),
        "already_configured": bool(existing),
    }


def extract_reply(res):
    """Never raises -- an unparseable body still returns something the
    caller can classify, rather than an exception that kills the run."""
    if isinstance(res, str):
        return res
    if isinstance(res, dict):
        for f in REPLY_FIELD_CANDIDATES:
            if f in res and isinstance(res[f], str):
                return res[f]
        if isinstance(res.get("choices"), list) and res["choices"]:
            c0 = res["choices"][0]
            if isinstance(c0, dict):
                msg = c0.get("message") or {}
                if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                    return msg["content"]
                if isinstance(c0.get("text"), str):
                    return c0["text"]
        if isinstance(res.get("data"), dict):
            return extract_reply(res["data"])
    return json.dumps(res)[:1000]


def call_endpoint(origin, endpoint, message, session_id, body_extra=None, timeout=DEFAULT_TIMEOUT):
    """One real POST. Never raises on a network/HTTP failure -- comes
    back in `error` so the caller can record an ERROR verdict instead of
    crashing the whole batch run. Always includes elapsed_ms; skills that
    don't need it (Jailbreaking/SensitiveInformation/OutputHandling)
    simply ignore that key."""
    body = {endpoint["message_field_guess"]: message}
    if endpoint.get("session_field_guess"):
        body[endpoint["session_field_guess"]] = session_id
    body.update(body_extra or {})  # ONLY explicit, user-supplied values -- never guessed

    req = urllib.request.Request(
        origin + endpoint["path"],
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method=endpoint.get("method", "POST"),
    )
    start = time.monotonic()

    def _elapsed():
        return int((time.monotonic() - start) * 1000)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        return {"request_body": body, "error": f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}",
                "response_text": None, "raw_response": None, "elapsed_ms": _elapsed()}
    except urllib.error.URLError as e:
        return {"request_body": body, "error": f"Connection failed: {e.reason}",
                "response_text": None, "raw_response": None, "elapsed_ms": _elapsed()}
    except (json.JSONDecodeError, TimeoutError) as e:
        return {"request_body": body, "error": f"Bad/no JSON response: {e}",
                "response_text": None, "raw_response": None, "elapsed_ms": _elapsed()}

    return {"request_body": body, "response_text": extract_reply(res), "raw_response": res,
            "error": None, "elapsed_ms": _elapsed()}


def run_burst(origin, endpoint, body_extra, prompt_text, count):
    """`count` real calls of the same prompt, fresh session each time.
    Returns one dict per call (call_endpoint's result + session_id).
    Aggregating these into burst_stats is run_prompt_entry's job, not
    this function's, so it stays reusable for any future burst shape."""
    calls = []
    for _ in range(count):
        session_id = str(uuid.uuid4())
        outcome = call_endpoint(origin, endpoint, prompt_text, session_id, body_extra)
        calls.append({"session_id": session_id, **outcome})
    return calls


def flag_duplicate_responses(results):
    """If 2+ prompts in THIS run got a byte-identical reply, that's
    near-certain evidence of a canned/rate-limited message -- computed
    fresh from this run's own outputs every time. Overlays onto (doesn't
    discard) the classifier's verdict."""
    def _overlay(get_text, get_verdict, set_verdict):
        counts = Counter(get_text(r) for r in results if r.get("sent") and get_text(r))
        for r in results:
            text = get_text(r)
            if text and counts[text] >= 2:
                set_verdict(r, f"DUPLICATE_RESPONSE ({counts[text]} of this run's prompts got a "
                                f"byte-identical reply -- almost certainly canned/rate-limited, not "
                                f"genuine engagement with this specific prompt; underlying heuristic "
                                f"verdict was: {get_verdict(r)})")

    _overlay(lambda r: r.get("response_text"), lambda r: r.get("verdict"), lambda r, v: r.__setitem__("verdict", v))
    _overlay(lambda r: r.get("followup_response_text"), lambda r: r.get("followup_verdict"), lambda r, v: r.__setitem__("followup_verdict", v))
    return results


def run_prompt_entry(origin, endpoint, resolved_extra, prompt_entry, classify_fn):
    """Sends one prompt dict (risk_id, prompt, optional followup_prompt/
    followup_same_session/burst/burst_count) and returns the full result
    entry. Shared by run_full's batch and run_one's single-row test so
    both take the exact same real path."""
    p = prompt_entry
    if p["prompt"] is None:
        return {**p, "sent": False, "session_id": None, "response_text": None,
                "raw_response": None, "error": None, "verdict": "NOT_APPLICABLE"}

    if p.get("burst"):
        calls = run_burst(origin, endpoint, resolved_extra, p["prompt"], p.get("burst_count", 1))
        last = calls[-1]
        errors = sum(1 for c in calls if c.get("error"))
        avg_elapsed_ms = sum(c.get("elapsed_ms", 0) for c in calls) // max(len(calls), 1)
        burst_stats = {"count": len(calls), "errors": errors, "avg_elapsed_ms": avg_elapsed_ms}
        entry = {**p, "sent": True, "session_id": last["session_id"],
                 "response_text": last.get("response_text"), "raw_response": last.get("raw_response"),
                 "error": last.get("error"), "elapsed_ms": last.get("elapsed_ms"),
                 "burst_calls": calls, "burst_stats": burst_stats}
        entry["verdict"] = classify_fn(p["risk_id"], last.get("response_text"),
                                        elapsed_ms=last.get("elapsed_ms"), burst_stats=burst_stats)
        return entry

    session_id = str(uuid.uuid4())
    outcome = call_endpoint(origin, endpoint, p["prompt"], session_id, resolved_extra)
    entry = {**p, "sent": True, "session_id": session_id, **outcome}
    entry["verdict"] = ("ERROR" if outcome.get("error")
                         else classify_fn(p["risk_id"], outcome.get("response_text"), elapsed_ms=outcome.get("elapsed_ms")))

    if p.get("followup_prompt"):
        followup_session = session_id if p.get("followup_same_session") else str(uuid.uuid4())
        followup_outcome = call_endpoint(origin, endpoint, p["followup_prompt"], followup_session, resolved_extra)
        entry["followup_session_id"] = followup_session
        entry["followup_response_text"] = followup_outcome.get("response_text")
        entry["followup_raw_response"] = followup_outcome.get("raw_response")
        entry["followup_error"] = followup_outcome.get("error")
        entry["followup_verdict"] = ("ERROR" if followup_outcome.get("error") else
                                      classify_fn(p["risk_id"], followup_outcome.get("response_text"),
                                                  elapsed_ms=followup_outcome.get("elapsed_ms")))

    return entry


def run_one(url, risk_id, prompt_text, *, build_prompts_fn, classify_fn, skill_dir,
            followup_prompt=None, followup_same_session=False, extra_fields=None):
    """Single, possibly user-edited prompt against the real endpoint --
    same learn phase as run_full. meaning/remediation/burst/burst_count
    are looked up from build_prompts_fn()'s own output for this risk_id,
    so a user-edited prompt still carries accurate OWASP grounding."""
    profile = site_analyzer.analyze(url)
    if profile.get("error") or not profile["is_llm_site"] or not profile["endpoints"]:
        return {"error": profile.get("error") or "Not an LLM site or no endpoint found for this URL.",
                "site_profile": profile}

    endpoint = pick_endpoint(url, profile["endpoints"])
    resolved_extra = {**load_overrides(url, skill_dir), **(extra_fields or {})}

    prompts = build_prompts_fn(
        profile["objective"],
        {"tool_use_hints": profile["tool_use_hints"], "attachment_hints": profile["attachment_hints"]},
    )
    ref = next((pr for pr in prompts if pr["risk_id"] == risk_id), {})

    p = {
        "risk_id": risk_id,
        "prompt": prompt_text,
        "followup_prompt": followup_prompt or None,
        "followup_same_session": bool(followup_same_session),
        "meaning": ref.get("meaning"),
        "remediation": ref.get("remediation"),
        "burst": ref.get("burst", False),
        "burst_count": ref.get("burst_count"),
    }
    entry = run_prompt_entry(profile["origin"], endpoint, resolved_extra, p, classify_fn)
    entry["endpoint_used"] = endpoint["path"]
    entry["target_url"] = url
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    return entry


def run_full(url, *, build_prompts_fn, classify_fn, probe_name, standard_citation, skill_dir,
             extra_fields=None, flag_duplicates=True):
    """Learn the site once, build every prompt, send+classify each
    sendable one, optionally flag duplicates, return the evidence dict
    every skill already writes today. Writing it to evidence/adversarial/
    stays the caller's job (skill-specific output filename prefix).
    flag_duplicates=False for UnboundedConsumption -- its original
    inject.py never ran this step, unlike the other three skills."""
    profile = site_analyzer.analyze(url)
    timestamp = datetime.now(timezone.utc).isoformat()

    evidence = {
        "probe_name": probe_name,
        "target_url": url,
        "timestamp": timestamp,
        "standard_citation": standard_citation,
        "site_profile": profile,
    }

    if profile.get("error"):
        evidence["verdict"] = "ERROR"
        evidence["results"] = []
        return evidence

    if not profile["is_llm_site"]:
        evidence["verdict"] = "NO LLM DETECTED -- this site does not have LLM"
        evidence["results"] = []
        return evidence

    if not profile["endpoints"]:
        evidence["verdict"] = "LLM INTERFACE DETECTED, BUT NO CALLABLE ENDPOINT CONTRACT COULD BE AUTO-DERIVED"
        evidence["results"] = []
        return evidence

    endpoint = pick_endpoint(url, profile["endpoints"])
    evidence["endpoint_used"] = endpoint["path"]

    resolved_extra = {**load_overrides(url, skill_dir), **(extra_fields or {})}
    unresolved = [f for f in endpoint.get("extra_fields", []) if f not in resolved_extra]
    if resolved_extra:
        evidence["endpoint_fields_supplied"] = {k: v for k, v in resolved_extra.items() if k in endpoint.get("extra_fields", [])}
    if unresolved:
        config_snippet = json.dumps({url: {f: "<fill in the real value for this field>" for f in unresolved}}, indent=2)
        evidence["endpoint_warning"] = (
            f"This endpoint's real request body also requires field(s) {unresolved} beyond "
            f"message/session, and this tool has no value for them (never guessed). Add this to "
            f"{_overrides_path(skill_dir)} and re-run:\n{config_snippet}\nWithout it, the endpoint may reject "
            f"the request or the live widget's real behavior may differ from what's recorded below."
        )
        evidence["config_snippet"] = config_snippet

    prompts = build_prompts_fn(
        profile["objective"],
        {"tool_use_hints": profile["tool_use_hints"], "attachment_hints": profile["attachment_hints"]},
    )

    results = [run_prompt_entry(profile["origin"], endpoint, resolved_extra, p, classify_fn) for p in prompts]
    if flag_duplicates:
        results = flag_duplicate_responses(results)

    evidence["verdict"] = "COMPLETE"
    evidence["results"] = results
    return evidence
