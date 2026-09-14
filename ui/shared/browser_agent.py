#!/usr/bin/env python3
"""
LLM-driven browser interaction -- IEM-AIS Platform Evolution Plan Phase 2.

For chatbots site_analyzer.py's regex-based endpoint detection can't reach
(a runtime-resolved fetch() URL, WebSocket streaming, a session-token-gated
call -- all confirmed live against Lakera's public "Agent Breaker"
challenge), this module drives the actual rendered page the way a human
tester would: open it in a real (Playwright) browser, ask an LLM which
element is the chat input and how to submit, type the prompt, wait for a
reply, read the resulting text back out of the DOM. It never assumes a
wire protocol underneath -- WebSocket, SSE, GraphQL, or plain REST all
become invisible, since this only interacts with the rendered page.

Used as a FALLBACK, never a replacement, for site_analyzer.py's fast
static-HTTP path -- inject_base.py only reaches for this when that path
finds no usable endpoint (see resolve_endpoint()/run_full() there).

New dependencies this module needs, NOT required by the rest of IEM-AIS:
  - `playwright` (+ `playwright install chromium`, a real browser binary)
    to actually construct and drive a `page` object -- this module itself
    never imports playwright; the caller (inject_base.py's fallback
    wiring) owns launching the browser and passes in the live Page.
  - an LLM call per prompt sent, to decide which element is the chat
    input. Prefers shelling out to the `claude` CLI's `-p` mode -- proven
    live (2026-09-14) to authenticate through this machine's own Claude
    Code login (a Pro/Max subscription's usage allowance, no separate
    per-token billing); falls back to a direct Anthropic API call
    (`ANTHROPIC_API_KEY`, real per-run cost) only if `claude` isn't on
    PATH. See _default_llm_call() below.
Both flagged plainly in README.md/CLAUDE.md, not left implicit.

Design choice that keeps this fully unit-testable with NEITHER dependency
installed: every function here takes its Playwright `page` and/or its LLM
call as a plain parameter, never constructs either itself. Real launching
of a browser, a real `claude -p` subprocess, or a real Anthropic client
only happen behind _default_llm_call() and in inject_base.py's own
fallback wiring (lazily imports `playwright`) -- so
tests/test_browser_agent.py exercises every real code path here (prompt
building, decision parsing/validation, the full send flow, the
reveal-click retry) against fake stand-ins, no network, no browser, no
subprocess, matching the project's existing no-network-in-pytest
convention.
"""

import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_LLM_MODEL = "claude-sonnet-5"
DEFAULT_REPLY_SETTLE_MS = 20_000

# Gitignored, repo-root-level -- holds saved Playwright storage_state()
# files (cookies/local storage) for chatbots behind a login. Keyed by
# ORIGIN, not full URL or skill: a login session is scoped to a domain,
# and every skill testing the same target should reuse the same saved
# session (Phase 2 step 4 -- see save_login_session() below).
AUTH_STATE_DIR = Path(__file__).resolve().parents[2] / ".browser_auth_state"


def _origin_key(url):
    p = urlparse(url)
    netloc = re.sub(r"[^A-Za-z0-9.-]", "_", p.netloc)
    return f"{p.scheme}_{netloc}" if netloc else "unknown_origin"


def auth_state_path(url):
    """Where a saved Playwright storage_state() for this URL's origin
    would live, if one has been saved via save_login_session() below.
    Never creates anything -- callers check .exists() themselves (see
    inject_base.open_browser_fallback())."""
    return AUTH_STATE_DIR / f"{_origin_key(url)}.json"


def save_login_session(url, headless=False):
    """Interactive, one-time setup -- run directly, never called from
    inject_base.py's automated path: opens a REAL, VISIBLE browser window
    to `url`, lets a human log in by hand, waits for them to confirm in
    the terminal, then saves the resulting session (cookies/local
    storage) via Playwright's storage_state() -- gitignored, treated as
    sensitive, reused by every later automated run against this origin.
    IEM-AIS never stores or guesses credentials itself; this only saves
    whatever session the human's own real login already produced."""
    from playwright.sync_api import sync_playwright  # only this interactive setup path needs it eagerly

    AUTH_STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = auth_state_path(url)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context()
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded")
        print(f"A browser window is now open at {url}.")
        print("Log in by hand in that window, then come back here and press Enter.")
        input()
        context.storage_state(path=str(path))
        browser.close()
    print(f"Saved session for this origin to {path}")
    return path

# Deliberately broad -- catches the usual shapes a chat input takes
# across arbitrary third-party UIs (plain textarea, bare <input>, a
# contenteditable div used by many rich-text chat widgets) plus anything
# that behaves like a button, so the LLM decision step has a genuinely
# complete inventory to choose from rather than a pre-narrowed guess.
INTERACTIVE_SELECTOR = (
    "textarea, input[type='text'], input:not([type]), "
    "[contenteditable='true'], [role='textbox'], button, "
    "[role='button'], input[type='submit']"
)

DECISION_PROMPT_TEMPLATE = """You are helping identify which element on a web page is a chat message input, purely from this text list of its interactive elements (index, tag, and any role/type/placeholder/aria-label/visible text). You are not being asked to bypass any security control -- only to identify a normal chat text box and its submit control, the same way a human tester reading the page would.

Elements:
{elements_text}

Reply with ONLY a JSON object, no other text, in exactly one of these two shapes:
1. {{"input_idx": <int>, "submit_idx": <int or null>, "submit_via_enter": <bool>}}
   -- input_idx is the chat message textbox; submit_idx is a send/submit
   button's index if one exists (null if there isn't one you can identify);
   submit_via_enter is true if pressing Enter in the input field should
   also be tried as a submission method.
2. {{"error": "<short honest reason you could not identify a chat input, e.g. 'no textbox-like element found'>"}}

Do not guess if you are not reasonably confident -- shape 2 is the correct, honest answer when nothing here looks like a chat input."""


def snapshot_interactive_elements(page, max_elements=60):
    """Simplified DOM-to-text extraction of the page's interactive
    surface -- text-only, no styling/layout, to keep the LLM call cheap
    (per Ramani's explicit choice: an LLM operates the browser itself,
    not hand-written per-site selectors). Each element gets a stable,
    re-selectable identifier (`data-iemais-idx`) written onto the live
    DOM so the later action step can re-find the EXACT element Playwright
    already looked at, not a fuzzy re-match that could drift."""
    return page.eval_on_selector_all(
        INTERACTIVE_SELECTOR,
        """(els, max) => els.slice(0, max).map((el, i) => {
            el.setAttribute('data-iemais-idx', String(i));
            return {
                idx: i,
                tag: el.tagName.toLowerCase(),
                role: el.getAttribute('role') || '',
                type: el.getAttribute('type') || '',
                placeholder: el.getAttribute('placeholder') || '',
                ariaLabel: el.getAttribute('aria-label') || '',
                text: (el.innerText || el.value || '').slice(0, 80),
            };
        })""",
        max_elements,
    )


def render_snapshot_text(elements):
    """The structured element list as the plain-text block sent to the
    LLM -- one line per element, stable idx first so the LLM's answer
    can point back at exactly one. Empty input is stated honestly rather
    than producing a blank prompt."""
    if not elements:
        return "(no interactive elements found on this page)"
    lines = []
    for el in elements:
        descriptors = []
        if el.get("role"):
            descriptors.append(f"role={el['role']}")
        if el.get("type"):
            descriptors.append(f"type={el['type']}")
        if el.get("placeholder"):
            descriptors.append(f"placeholder=\"{el['placeholder']}\"")
        if el.get("ariaLabel"):
            descriptors.append(f"aria-label=\"{el['ariaLabel']}\"")
        if el.get("text"):
            descriptors.append(f"text=\"{el['text']}\"")
        lines.append(f"[{el['idx']}] <{el['tag']}> {' '.join(descriptors)}")
    return "\n".join(lines)


def build_decision_prompt(elements_text):
    return DECISION_PROMPT_TEMPLATE.format(elements_text=elements_text)


def parse_decision(raw_llm_text, num_elements):
    """Parses the LLM's raw text reply into a validated action dict or an
    honest failure -- NEVER raises, NEVER guesses past what the LLM
    actually said. A malformed/verbose/off-spec/out-of-range reply is
    treated the same as an honest "could not identify" ({"error": ...}),
    never silently coerced into an action -- this is the one place a
    hallucinated element reference gets caught before it ever reaches
    Playwright."""
    if not raw_llm_text:
        return {"error": "LLM returned no text."}
    match = re.search(r"\{.*\}", raw_llm_text, re.DOTALL)
    if not match:
        return {"error": f"LLM reply had no JSON object: {raw_llm_text[:200]!r}"}
    try:
        decision = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {"error": f"LLM reply was not valid JSON: {raw_llm_text[:200]!r}"}
    if not isinstance(decision, dict):
        return {"error": "LLM reply JSON was not an object."}
    if "error" in decision:
        return {"error": str(decision["error"])}
    if "input_idx" not in decision:
        return {"error": "LLM reply JSON had neither 'error' nor 'input_idx'."}
    try:
        input_idx = int(decision["input_idx"])
    except (TypeError, ValueError):
        return {"error": "LLM reply's input_idx was not an integer."}
    if not (0 <= input_idx < num_elements):
        return {"error": f"LLM reply's input_idx {input_idx} is out of range for {num_elements} elements."}
    submit_idx = decision.get("submit_idx")
    if submit_idx is not None:
        try:
            submit_idx = int(submit_idx)
        except (TypeError, ValueError):
            return {"error": "LLM reply's submit_idx was not an integer or null."}
        if not (0 <= submit_idx < num_elements):
            return {"error": f"LLM reply's submit_idx {submit_idx} is out of range for {num_elements} elements."}
    return {
        "input_idx": input_idx,
        "submit_idx": submit_idx,
        "submit_via_enter": bool(decision.get("submit_via_enter", True)),
    }


def _llm_call_via_cli(prompt_text, timeout=60):
    """Shells out to `claude -p` (Claude Code's non-interactive print
    mode), prompt piped via stdin -- confirmed live (2026-09-14) to
    authenticate through whatever this machine's own Claude Code login
    already is (a Pro/Max subscription's own usage allowance included)
    rather than a separate pay-per-token Anthropic API key: a real
    `claude -p` call succeeded on this project's own dev machine at the
    exact moment its ANTHROPIC_API_KEY had a zero credit balance and was
    rejecting direct API calls outright. Preferred default over
    _llm_call_via_api below for exactly that reason -- most people
    running this tool already have Claude Code installed and logged in,
    and this needs no extra billing setup at all."""
    import shutil
    import subprocess

    # On Windows, an npm-installed CLI is a .cmd shim -- CreateProcess (what
    # subprocess uses with shell=False) can't resolve a bare "claude" to
    # that shim itself the way a real shell's PATHEXT lookup would, so this
    # must resolve the actual executable path first (confirmed live: a bare
    # "claude" raised FileNotFoundError on this dev machine despite `which
    # claude` finding it, while the shutil.which()-resolved full path ran
    # successfully). shutil.which() is cross-platform-safe -- it's a no-op
    # equivalent on Linux/macOS, where "claude" is already a real executable.
    claude_path = shutil.which("claude")
    if claude_path is None:
        raise RuntimeError(
            "The `claude` CLI was not found on PATH -- see _llm_call_via_api "
            "for the alternative ANTHROPIC_API_KEY-based path."
        )
    try:
        # The prompt is piped via stdin, NOT passed as a CLI argument --
        # confirmed live: this decision prompt is multi-line (one page
        # element per line), and passing it as an argv element through the
        # Windows .cmd shim's own cmd.exe-based invocation silently mangled
        # the embedded newlines, so the LLM received no element list at
        # all. Piping via stdin (`claude -p` with no positional prompt)
        # reproduced correctly and is also simpler/safer on every platform
        # (no shell-quoting of arbitrary prompt text at all).
        result = subprocess.run(
            [claude_path, "-p"],
            input=prompt_text, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "The `claude` CLI was not found on PATH -- see _llm_call_via_api "
            "for the alternative ANTHROPIC_API_KEY-based path."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"`claude -p` did not respond within {timeout}s.")
    if result.returncode != 0:
        raise RuntimeError(f"`claude -p` failed (exit {result.returncode}): {result.stderr.strip()[:300]}")
    return result.stdout.strip()


def _llm_call_via_api(prompt_text):
    """Direct Anthropic API call -- imports `anthropic` lazily so merely
    importing browser_agent.py never requires that package. Fallback path
    for a machine without the `claude` CLI installed; requires its own
    pay-per-token ANTHROPIC_API_KEY (a real per-run cost), unlike
    _llm_call_via_cli above."""
    import os
    import anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Neither the `claude` CLI nor ANTHROPIC_API_KEY is available -- "
            "browser_agent.py needs one of the two to decide which page "
            "element is the chat input (Project DOCS/"
            "IEM-AIS-Platform-Evolution-Plan.md Phase 2). Install Claude "
            "Code (preferred, no separate billing) or set "
            "ANTHROPIC_API_KEY, then retry."
        )
    client = anthropic.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=DEFAULT_LLM_MODEL,
        max_tokens=300,
        messages=[{"role": "user", "content": prompt_text}],
    )
    return "".join(block.text for block in resp.content if getattr(block, "type", None) == "text")


def _default_llm_call(prompt_text):
    """Prefers the `claude` CLI (see _llm_call_via_cli -- no separate
    billing, reuses this machine's own Claude Code login) when it's on
    PATH; falls back to a direct Anthropic API call (ANTHROPIC_API_KEY)
    otherwise, for a machine that has an API key but not Claude Code
    itself installed."""
    import shutil

    if shutil.which("claude"):
        return _llm_call_via_cli(prompt_text)
    return _llm_call_via_api(prompt_text)


REVEAL_CANDIDATE_RE = re.compile(r"\b(chat|message|ask|talk|assistant)\b", re.IGNORECASE)
REVEAL_CLICK_WAIT_MS = 2000
REVEAL_CLICK_TIMEOUT_MS = 5000


def _find_reveal_candidates(elements):
    """Every element whose visible text/aria-label suggests it opens/
    reveals a chat panel, in DOM order -- confirmed live (2026-09-14)
    against Lakera's public "Agent Breaker" challenge, whose real chat
    `<textarea>` doesn't exist in the DOM at all until a "Chat" tab button
    is clicked, AND which has more than one similarly-labeled element
    (e.g. a nav-tab "Chat" plus a separate in-page "Chat" toggle) where
    only one is actually clickable at a given moment -- confirmed live:
    the first match alone timed out waiting to become actionable, while a
    later match with the same label worked. send_prompt_via_browser()
    below tries each in turn with a short per-click timeout rather than
    betting everything on the first. This is still only ever a guess at
    what to CLICK to reveal more UI -- never at what to TYPE into -- so it
    stays honest: if none of these reveal a real input, the caller still
    returns an honest error, never a fabricated reply."""
    return [el for el in elements
            if REVEAL_CANDIDATE_RE.search(f"{el.get('text', '')} {el.get('ariaLabel', '')}")]


def identify_chat_action(elements, llm_call=None):
    """elements: snapshot_interactive_elements()'s output. llm_call: an
    injectable prompt_text->raw_text function (defaults to a real
    Anthropic call) -- this seam is what makes this function (and
    send_prompt_via_browser below) testable with zero network/LLM calls."""
    llm_call = llm_call or _default_llm_call
    if not elements:
        return {"error": "No interactive elements found on this page at all."}
    raw = llm_call(build_decision_prompt(render_snapshot_text(elements)))
    return parse_decision(raw, len(elements))


def send_prompt_via_browser(page, prompt_text, *, llm_call=None, reply_wait_ms=DEFAULT_REPLY_SETTLE_MS):
    """Drives one real prompt through `page` via Playwright, using
    identify_chat_action() to find the input/submit controls. Returns a
    dict shaped exactly like inject_base.call_endpoint()'s contract
    (response_text/raw_response/error/elapsed_ms) so inject_base.py can
    use this as a drop-in fallback with ZERO changes to any skill's
    classifier. Never fabricates a reply and never returns a false
    NOT_APPLICABLE -- an identification failure, a vanished element, or a
    reply that never appears within the wait window all come back as
    `error`, exactly like a failed HTTP call already does."""
    start = time.monotonic()

    def _elapsed():
        return int((time.monotonic() - start) * 1000)

    try:
        elements = snapshot_interactive_elements(page)
        decision = identify_chat_action(elements, llm_call=llm_call)
        if "error" in decision:
            # Some chat widgets (confirmed live against Lakera's Agent
            # Breaker) don't render their real input into the DOM until a
            # "Chat"-labeled tab/button is clicked first. Try each such
            # reveal candidate in turn, the way a human tester poking at
            # visible options would, with a SHORT per-click timeout so one
            # non-actionable candidate (confirmed live: this can happen
            # even for a visibly-labeled element) doesn't eat 30s before
            # moving on -- re-snapshotting and re-asking after any click
            # that actually succeeds, stopping at the first one that works.
            # Still never guesses at what to TYPE, only at what to click.
            for candidate in _find_reveal_candidates(elements):
                reveal_el = page.query_selector(f"[data-iemais-idx='{candidate['idx']}']")
                if reveal_el is None:
                    continue
                try:
                    reveal_el.click(timeout=REVEAL_CLICK_TIMEOUT_MS)
                except Exception:
                    continue  # this candidate wasn't actually clickable -- try the next one
                page.wait_for_timeout(REVEAL_CLICK_WAIT_MS)
                elements = snapshot_interactive_elements(page)
                decision = identify_chat_action(elements, llm_call=llm_call)
                if "error" not in decision:
                    break
    except Exception as e:
        # Covers a missing LLM call path, a network/auth failure calling
        # it, or a Playwright failure taking the snapshot/reveal-click --
        # none of this may ever crash the whole batch run; it's an honest
        # ERROR entry for this one prompt, same contract call_endpoint()
        # already has for a failed HTTP call.
        return {"response_text": None, "raw_response": None,
                "error": f"Could not identify a usable chat input: {e}",
                "elapsed_ms": _elapsed()}
    if "error" in decision:
        return {"response_text": None, "raw_response": None,
                "error": f"Could not identify a usable chat input: {decision['error']}",
                "elapsed_ms": _elapsed()}

    input_el = page.query_selector(f"[data-iemais-idx='{decision['input_idx']}']")
    if input_el is None:
        return {"response_text": None, "raw_response": None,
                "error": "Identified input element vanished from the page before it could be used.",
                "elapsed_ms": _elapsed()}

    try:
        before_text = page.inner_text("body") or ""
        input_el.click()
        input_el.fill(prompt_text)

        submitted = False
        if decision.get("submit_idx") is not None:
            submit_el = page.query_selector(f"[data-iemais-idx='{decision['submit_idx']}']")
            if submit_el is not None:
                submit_el.click()
                submitted = True
        if not submitted and decision.get("submit_via_enter", True):
            input_el.press("Enter")
            submitted = True
        if not submitted:
            return {"response_text": None, "raw_response": None,
                    "error": "Identified an input but no way to submit it (no submit button found, Enter not offered).",
                    "elapsed_ms": _elapsed()}

        page.wait_for_timeout(reply_wait_ms)
        after_text = page.inner_text("body") or ""
    except Exception as e:  # Playwright raises its own exception types on timeout/detach -- any of
                             # them is an honest ERROR here, never a crash of the whole batch run.
        return {"response_text": None, "raw_response": None,
                "error": f"Browser interaction failed: {e}", "elapsed_ms": _elapsed()}

    new_text = after_text[len(before_text):] if after_text.startswith(before_text) else after_text
    reply_text = new_text.strip() or None
    if reply_text is None:
        return {"response_text": None, "raw_response": {"page_text_after": after_text[:2000]},
                "error": "No new text appeared on the page within the wait window -- the reply may not "
                         "have arrived yet, or is rendered somewhere this before/after body-text "
                         "heuristic didn't capture. Verify manually before concluding anything.",
                "elapsed_ms": _elapsed()}

    return {"response_text": reply_text, "raw_response": {"page_text_after": after_text[:2000]},
            "error": None, "elapsed_ms": _elapsed()}


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "login":
        save_login_session(sys.argv[2])
    else:
        print("Usage: python browser_agent.py login <url>", file=sys.stderr)
        sys.exit(1)
