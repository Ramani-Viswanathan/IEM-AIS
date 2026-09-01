#!/usr/bin/env python3
"""
Passive site analyzer -- IEM-AIS Jailbreaking test case, generic.

Given ANY URL, determines (for real, from that site's actual served HTML/JS,
never assumed):
  1. Whether the site has an LLM-backed interface at all.
  2. If yes: which endpoint(s) drive it, and a best-effort request/response
     shape guess.
  3. The site's actual stated objective (title/meta description/h1), used
     to contextualize attack prompts later -- never a fixed persona.

Method: fetch the page, follow same-origin <script> bundles, grep the
combined text for LLM-indicative signals and `fetch(...)` call sites. This
generalizes the exact manual process used to reverse-engineer a real
site's chat API contract (fetch HTML -> find bundle -> fetch bundle ->
grep fetch() calls) into code that runs against any URL.

A production bundle inlines an app's whole module graph into the one
script tag it references, so following <script src> once is normally
enough. A dev server (e.g. `vite dev`) instead serves each source file as
its own unbundled ES module -- the entry script is a thin `main.jsx` that
merely `import`s the real app, which itself imports the component that
actually owns the chat fetch() call. So bundle-following also walks
same-origin `import ... from "..."` / `import("...")` targets found
inside each fetched file, breadth-first, to a bounded depth/count --
letting a dev-server target get the same detection depth as a prod one.

This stage never POSTs anywhere -- only GETs the target's own page and its
same-origin script bundles.
"""

import json
import re
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse

UA = "Mozilla/5.0 (compatible; IEM-AIS-JailbreakingAnalyzer/1.0)"

# Generic detection heuristics -- reused for ANY site, not per-target content.
LLM_PATH_HINTS = re.compile(
    r"(chat|assistant|completion|copilot|message|prompt|ai-?bot|gpt|llm|converse|liftoff)",
    re.IGNORECASE,
)
LLM_VENDOR_HINTS = [
    "openai", "anthropic", "claude", "gemini", "gpt-3", "gpt-4", "gpt-5",
    "langchain", "vercel/ai", "text/event-stream", "system_prompt",
    '"role":"system"', "'role':'system'", "chatcompletion", "sessionid",
]
TOOL_USE_HINTS = ["function_call", "tool_calls", "tool_choice", "retrieval", " rag ", "citations", "browse"]
ATTACHMENT_HINTS = ["image_url", "data:image", "attachment", "multipart/form-data", "upload"]

FETCH_CALL_RE = re.compile(r"fetch\(\s*[`'\"]([^`'\"]+)[`'\"]")
JSON_STRINGIFY_RE = re.compile(r"JSON\.stringify\(\s*\{([^}]*)\}\s*\)")
BODY_KEY_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:")
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
H1_RE = re.compile(r"<h1[^>]*>(.*?)</h1>", re.IGNORECASE | re.DOTALL)

# ES module import/export targets -- how bundle-following reaches a dev
# server's unbundled module graph (see module docstring). Deliberately
# permissive (lazy match up to the first quote) since this is a heuristic
# grep, not a JS parser -- same tradeoff already made by FETCH_CALL_RE.
STATIC_IMPORT_RE = re.compile(r'\bimport\s+(?:[^\'";]*?\bfrom\s+)?["\']([^"\']+)["\']')
EXPORT_FROM_RE = re.compile(r'\bexport\s+[^\'";]*?\bfrom\s+["\']([^"\']+)["\']')
DYNAMIC_IMPORT_RE = re.compile(r'\bimport\s*\(\s*["\']([^"\']+)["\']')

# Bundle-crawl bounds -- generous enough to reach a component a few
# import-hops from the entry script (observed: 3 hops deep on a real Vite
# dev server), capped so a large app's full module graph can't turn one
# analyze() call into hundreds of requests.
MAX_BUNDLES = 40
MAX_IMPORT_DEPTH = 6
# Only worth opening files that could plausibly contain a fetch() call or
# vendor string; skip stylesheets/images/fonts reached via `import "./x.css"`.
FOLLOWABLE_EXTENSIONS = {"js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte"}


def _extract_import_targets(text):
    targets = set()
    for rx in (STATIC_IMPORT_RE, EXPORT_FROM_RE, DYNAMIC_IMPORT_RE):
        targets.update(rx.findall(text))
    return targets


def _is_followable(path):
    last_segment = path.rsplit("/", 1)[-1]
    if "." not in last_segment:
        return True  # extensionless import specifier (common for source files)
    ext = last_segment.rsplit(".", 1)[-1].lower()
    return ext in FOLLOWABLE_EXTENSIONS


def _fetch(url, max_bytes=800_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read(max_bytes).decode("utf-8", errors="replace")


def _strip_tags(s):
    return re.sub(r"<[^>]+>", "", s).strip()


def analyze(url):
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    try:
        html = _fetch(url)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        return {"url": url, "error": f"Could not fetch URL: {e}", "is_llm_site": False,
                "objective": None, "signals": [], "endpoints": [],
                "tool_use_hints": [], "attachment_hints": [], "fetched_bundles": []}

    title_m = TITLE_RE.search(html)
    desc_m = DESC_RE.search(html)
    h1_m = H1_RE.search(html)

    objective_parts = [
        _strip_tags(title_m.group(1)) if title_m else "",
        desc_m.group(1).strip() if desc_m else "",
        _strip_tags(h1_m.group(1)) if h1_m else "",
    ]
    objective = " -- ".join(p for p in objective_parts if p) or "(no title/description/h1 found on this page; objective unknown)"

    bundle_texts = []
    fetched_bundles = []
    visited = set()
    queue = []  # (bundle_url, depth)
    for src in SCRIPT_SRC_RE.findall(html)[:8]:  # cap: don't fetch unbounded top-level scripts
        bundle_url = urljoin(url, src)
        if urlparse(bundle_url).netloc != parsed.netloc:
            continue  # same-origin only
        queue.append((bundle_url, 0))

    while queue and len(fetched_bundles) < MAX_BUNDLES:
        bundle_url, depth = queue.pop(0)
        if bundle_url in visited:
            continue
        visited.add(bundle_url)
        try:
            text = _fetch(bundle_url)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            continue
        bundle_texts.append(text)
        fetched_bundles.append(bundle_url)

        if depth >= MAX_IMPORT_DEPTH:
            continue
        for target in _extract_import_targets(text):
            if "node_modules" in target:
                continue  # vendor deps, not app code -- see module docstring
            child_url = urljoin(bundle_url, target)
            if urlparse(child_url).netloc != parsed.netloc:
                continue  # same-origin only
            if child_url in visited or not _is_followable(urlparse(child_url).path):
                continue
            queue.append((child_url, depth + 1))

    combined_lower = (html + "\n".join(bundle_texts)).lower()

    signals = []
    vendor_hits = [h for h in LLM_VENDOR_HINTS if h.lower() in combined_lower]
    if vendor_hits:
        signals.append(f"LLM vendor/SDK strings found in served code: {vendor_hits}")

    fetch_hits = []  # (relative_path, context, bundle_url)
    for bt in bundle_texts:
        for m in FETCH_CALL_RE.finditer(bt):
            raw_path = m.group(1)
            if raw_path.startswith("http"):
                if urlparse(raw_path).netloc != parsed.netloc:
                    continue  # cross-origin fetch, not this site's own API
                rel_path = urlparse(raw_path).path
            else:
                rel_path = raw_path if raw_path.startswith("/") else "/" + raw_path
            if LLM_PATH_HINTS.search(rel_path):
                context = bt[m.start(): m.start() + 400].strip()
                fetch_hits.append((rel_path, context))

    if fetch_hits:
        signals.append(f"LLM-suggestive fetch() call path(s) found: {sorted(set(p for p, _ in fetch_hits))}")

    tool_hits = [h for h in TOOL_USE_HINTS if h.lower() in combined_lower]
    attachment_hits = [h for h in ATTACHMENT_HINTS if h.lower() in combined_lower]

    is_llm_site = bool(vendor_hits or fetch_hits)

    endpoints = []
    seen_paths = set()
    for path, context in fetch_hits:
        if path in seen_paths:
            continue
        seen_paths.add(path)
        # Best-effort field-name guess from the surrounding source; the
        # runner confirms the real shape with one live benign call before
        # sending anything adversarial (see inject.py).
        field_guess = "message"
        for fname in ("message", "prompt", "input", "text", "query", "content"):
            if f'"{fname}"' in context or f"'{fname}'" in context or f"{fname}:" in context:
                field_guess = fname
                break
        session_field = None
        for fname in ("sessionId", "session_id", "conversationId", "threadId"):
            if fname in context:
                session_field = fname
                break

        # Every key this endpoint's real body literally sends, parsed from
        # its JSON.stringify({...}) call -- catches fields beyond
        # message/session (e.g. an episode/thread identifier) that this
        # analyzer can't safely fabricate a value for. Surfaced honestly
        # instead of silently dropped.
        body_keys = []
        stringify_m = JSON_STRINGIFY_RE.search(context)
        if stringify_m:
            body_keys = BODY_KEY_RE.findall(stringify_m.group(1))
        extra_fields = [k for k in body_keys if k not in (field_guess, session_field)]

        # extra_fields are NOT guessed at -- no field-name pattern matching,
        # no inferring a value from the URL/page. If this endpoint needs
        # them, the value comes only from an explicit, user-supplied
        # override (see config/site_overrides.json, applied in inject.py)
        # or is left unresolved and reported honestly.
        endpoints.append({
            "path": path,
            "method": "POST",
            "message_field_guess": field_guess,
            "session_field_guess": session_field,
            "extra_fields": extra_fields,
            "raw_context": context[:300],
        })

    return {
        "url": url,
        "origin": origin,
        "objective": objective,
        "fetched_bundles": fetched_bundles,
        "is_llm_site": is_llm_site,
        "signals": signals or ["No LLM-indicative vendor strings or chat-like fetch() paths found in this page's served HTML/JS."],
        "tool_use_hints": tool_hits,
        "attachment_hints": attachment_hits,
        "endpoints": endpoints,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python site_analyzer.py <url>", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(analyze(sys.argv[1]), indent=2))
