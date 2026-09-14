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

# Reserved key inside a URL's site_overrides.json entry: a human-confirmed,
# full endpoint contract (path/method/field names/headers) to use INSTEAD OF
# site_analyzer.py's auto-guessed endpoint list. Exists for real targets
# (confirmed live against Lakera's Agent Breaker) where the chat request URL
# is only resolved once the page's own JS runs (a bundled variable, not a
# literal fetch() string) -- no static regex can ever recover that. Kept
# separate from the flat body-extra-field keys already in this same dict so
# the two mechanisms (endpoint override vs. extra body fields) can combine
# freely -- see Project DOCS/IEM-AIS-Platform-Evolution-Plan.md Phase 2 step 1.
ENDPOINT_OVERRIDE_KEY = "_endpoint_override"


def _overrides_path(skill_dir):
    return Path(skill_dir) / "config" / "site_overrides.json"


def load_overrides(url, skill_dir):
    """Explicit, user-supplied field values ONLY. Nothing here is guessed
    or derived; an absent/unmatched entry just means no override exists.
    May include the reserved ENDPOINT_OVERRIDE_KEY alongside plain body
    fields -- callers that only want body fields use
    extra_fields_from_overrides() below."""
    path = _overrides_path(skill_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data.get(url, {})


def extra_fields_from_overrides(overrides):
    """The plain body-extra-field values out of a load_overrides() dict --
    strips the reserved endpoint-override key, which is config for HOW to
    reach the endpoint, not a value to stuff into the request body."""
    return {k: v for k, v in overrides.items() if k != ENDPOINT_OVERRIDE_KEY}


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


def resolve_endpoint(url, profile, skill_dir):
    """The endpoint to actually call for this run: an explicit, human-
    confirmed override (site_overrides.json's ENDPOINT_OVERRIDE_KEY) if one
    exists for this URL, otherwise site_analyzer.py's auto-guessed
    pick_endpoint() result. An override is honored even when
    profile["endpoints"] is empty -- that emptiness is exactly the gap this
    mechanism exists to cover. Returns None when neither source has
    anything to offer, same contract pick_endpoint() already had."""
    overrides = load_overrides(url, skill_dir)
    override = overrides.get(ENDPOINT_OVERRIDE_KEY)
    if override:
        return {
            "path": override["path"],
            "method": override.get("method", "POST"),
            "message_field_guess": override.get("message_field_guess", "message"),
            "session_field_guess": override.get("session_field_guess"),
            "extra_fields": [],  # already-resolved via this same overrides dict's body fields
            "headers": override.get("headers") or {},
        }
    endpoint = pick_endpoint(url, profile.get("endpoints") or [])
    if endpoint is not None and "headers" not in endpoint:
        endpoint = {**endpoint, "headers": {}}
    return endpoint


def describe_config_needs(url, profile, skill_dir):
    """What's missing before results for THIS site are trustworthy --
    computed fresh per site, never templated from another target."""
    if not profile.get("is_llm_site"):
        return None
    endpoint = resolve_endpoint(url, profile, skill_dir)
    if endpoint is None:
        return None

    existing = extra_fields_from_overrides(load_overrides(url, skill_dir))
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
    simply ignore that key.

    endpoint["path"] may be a full absolute URL (an explicit endpoint
    override can point at a different host than the page itself, e.g. a
    separate api.* origin) -- otherwise it's joined onto `origin` as
    before. endpoint["headers"], if present (only ever human-supplied via
    an override -- see ENDPOINT_OVERRIDE_KEY), is merged in alongside the
    default Content-Type, e.g. for a session-token-gated endpoint's
    Authorization header."""
    body = {endpoint["message_field_guess"]: message}
    if endpoint.get("session_field_guess"):
        body[endpoint["session_field_guess"]] = session_id
    body.update(body_extra or {})  # ONLY explicit, user-supplied values -- never guessed

    target = endpoint["path"] if endpoint["path"].startswith(("http://", "https://")) else origin + endpoint["path"]
    headers = {"Content-Type": "application/json", **(endpoint.get("headers") or {})}
    req = urllib.request.Request(
        target,
        data=json.dumps(body).encode(),
        headers=headers,
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


def _send_via_endpoint(origin, endpoint, message, session_id, body_extra=None, timeout=DEFAULT_TIMEOUT):
    """Dispatches to the real HTTP call_endpoint(), or -- when `endpoint`
    carries mode="browser" (site_analyzer.py found no usable endpoint and
    no override exists; see open_browser_fallback() and run_full() below)
    -- to browser_agent.send_prompt_via_browser() instead. Both return the
    exact same shape (response_text/raw_response/error/elapsed_ms), so
    every caller downstream (run_prompt_entry, run_burst, every skill's
    classify()) needs ZERO changes to work with either path. `browser_agent`
    is imported lazily here, not at module load, so a normal HTTP-only run
    never needs playwright installed at all."""
    if endpoint.get("mode") == "browser":
        import browser_agent
        return browser_agent.send_prompt_via_browser(endpoint["page"], message, llm_call=endpoint.get("llm_call"))
    return call_endpoint(origin, endpoint, message, session_id, body_extra, timeout)


def open_browser_fallback(url):
    """Launches a real, headless Playwright Chromium browser, navigates to
    url, and returns {"page": page, "close": fn} -- or None if playwright
    isn't installed, or the page couldn't be reached at all, so run_full()
    can fall through to the existing honest "no callable endpoint" verdict
    rather than crashing. This is the ONLY place in inject_base.py that
    ever imports playwright, and only when the fast HTTP path has already
    failed to find an endpoint (see run_full()) -- see
    Project DOCS/IEM-AIS-Platform-Evolution-Plan.md Phase 2 step 2-3."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    import browser_agent  # for auth_state_path() -- Phase 2 step 4, saved logins

    pw = None
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        state_path = browser_agent.auth_state_path(url)
        context = (browser.new_context(storage_state=str(state_path)) if state_path.exists()
                   else browser.new_context())
        page = context.new_page()
        page.goto(url, timeout=30_000, wait_until="domcontentloaded")
    except Exception:
        if pw is not None:
            try:
                pw.stop()
            except Exception:
                pass
        return None

    def _close():
        try:
            browser.close()
        finally:
            pw.stop()

    return {"page": page, "close": _close}


def run_burst(origin, endpoint, body_extra, prompt_text, count):
    """`count` real calls of the same prompt, fresh session each time.
    Returns one dict per call (call_endpoint's result + session_id).
    Aggregating these into burst_stats is run_prompt_entry's job, not
    this function's, so it stays reusable for any future burst shape.
    In browser-fallback mode there's no real fresh-session concept (every
    call reuses the same page/session; see run_full()'s
    browser_fallback_note) -- session_id here is still generated per call
    for shape-compatibility with the HTTP path's evidence records only."""
    calls = []
    for _ in range(count):
        session_id = str(uuid.uuid4())
        outcome = _send_via_endpoint(origin, endpoint, prompt_text, session_id, body_extra)
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
    outcome = _send_via_endpoint(origin, endpoint, p["prompt"], session_id, resolved_extra)
    entry = {**p, "sent": True, "session_id": session_id, **outcome}
    entry["verdict"] = ("ERROR" if outcome.get("error")
                         else classify_fn(p["risk_id"], outcome.get("response_text"), elapsed_ms=outcome.get("elapsed_ms")))

    if p.get("followup_prompt"):
        followup_session = session_id if p.get("followup_same_session") else str(uuid.uuid4())
        followup_outcome = _send_via_endpoint(origin, endpoint, p["followup_prompt"], followup_session, resolved_extra)
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
    if profile.get("error") or not profile["is_llm_site"]:
        return {"error": profile.get("error") or "Not an LLM site or no endpoint found for this URL.",
                "site_profile": profile}

    endpoint = resolve_endpoint(url, profile, skill_dir)
    browser_ctx = None
    if endpoint is None:
        browser_ctx = open_browser_fallback(url)  # see run_full()'s fuller comment on this mechanism
        if browser_ctx is None:
            return {"error": "Not an LLM site or no endpoint found for this URL.", "site_profile": profile}
        endpoint = {"mode": "browser", "path": "(browser-driven, no fixed endpoint path)",
                    "page": browser_ctx["page"], "extra_fields": []}
    resolved_extra = {**extra_fields_from_overrides(load_overrides(url, skill_dir)), **(extra_fields or {})}

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
    try:
        entry = run_prompt_entry(profile["origin"], endpoint, resolved_extra, p, classify_fn)
    finally:
        if browser_ctx is not None:
            browser_ctx["close"]()
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

    endpoint = resolve_endpoint(url, profile, skill_dir)
    browser_ctx = None
    if endpoint is None:
        # The fast static-HTTP path found nothing (site_analyzer.py's
        # regex-based fetch() detection can't resolve a runtime-built URL,
        # WebSocket-streamed chat, or a session-token-gated call -- confirmed
        # live against Lakera's Agent Breaker). Fall back to driving the
        # real rendered page with an LLM-operated browser instead of giving
        # up -- see Project DOCS/IEM-AIS-Platform-Evolution-Plan.md Phase 2.
        # A no-op (returns None) if playwright isn't installed or the page
        # can't be reached at all, so this never regresses the pre-Phase-2
        # behavior on a machine without that optional dependency.
        browser_ctx = open_browser_fallback(url)
        if browser_ctx is None:
            evidence["verdict"] = "LLM INTERFACE DETECTED, BUT NO CALLABLE ENDPOINT CONTRACT COULD BE AUTO-DERIVED"
            evidence["results"] = []
            return evidence
        endpoint = {"mode": "browser", "path": "(browser-driven, no fixed endpoint path)",
                    "page": browser_ctx["page"], "extra_fields": []}
        evidence["browser_fallback_used"] = True
        evidence["browser_fallback_note"] = (
            "site_analyzer.py found no callable HTTP endpoint contract for this site, so every "
            "prompt below was sent by driving the real rendered page in a Playwright-controlled "
            "browser, with an LLM identifying the chat input each time -- all within ONE continuous "
            "browser session/page, unlike the HTTP path's fresh session per prompt. The model may "
            "therefore retain earlier prompts' context across this run's results. Verify manually, "
            "same as every other verdict this tool produces."
        )
    evidence["endpoint_used"] = endpoint["path"]

    overrides = load_overrides(url, skill_dir)
    resolved_extra = {**extra_fields_from_overrides(overrides), **(extra_fields or {})}
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

    try:
        results = [run_prompt_entry(profile["origin"], endpoint, resolved_extra, p, classify_fn) for p in prompts]
    finally:
        if browser_ctx is not None:
            browser_ctx["close"]()
    if flag_duplicates:
        results = flag_duplicate_responses(results)

    evidence["verdict"] = "COMPLETE"
    evidence["results"] = results
    return evidence
