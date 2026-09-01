#!/usr/bin/env python3
"""
Shared UI backend -- serves BOTH test cases (Jailbreaking, Sensitive
Information) from one page, per-test-case logic staying owned by each
test case's own folder/SKILL.md (see TEST_CASES below). Adding a Test
Case 3 later means adding one entry here and one sibling folder -- this
file and index.html don't need test-case-specific code.

Stdlib-only (no Flask/FastAPI): serves index.html and three JSON
endpoints that call each test case's real inject.py/prompt_generator.py
directly (no subprocess, no mock).

  GET  /                        -> index.html
  POST /api/analyze             -> {"url": "..."}
                                    => site_analyzer.analyze(url) ONCE
                                    (shared learn phase, one fetch), then
                                    per test case: config_needs + prompts
  POST /api/test                -> {"url": "...", "test_case": "..."}
                                    => that test case's inject.run_full(url)
  POST /api/test_one            -> {"url": "...", "test_case": "...",
                                     "risk_id": N, "prompt": "..."}
                                    => that test case's inject.run_one(...)

Usage:
    python server.py [--port 8787]
    then open http://localhost:8787/ in a browser.

Module-loading gotcha (why this isn't three plain `import`s): both test
cases have their own inject.py and prompt_generator.py, same file names,
different content. A plain `import inject` from two different skill
folders would silently return the FIRST one loaded (Python caches by
module name in sys.modules) -- the second test case would run using the
first test case's prompts. _load_test_case() below loads each pair under
a distinct sys.modules name and explicitly primes sys.modules["prompt_generator"]
right before exec'ing each inject.py, so each skill's internal
`import prompt_generator` binds to ITS OWN sibling module, not the other
test case's. Verified this session: both test cases' /api/test calls
return their own distinct risk sets, not a shared/overwritten one.
"""

import argparse
import importlib.util
import json
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

UI_DIR = Path(__file__).resolve().parent
IEM_AIS_ROOT = UI_DIR.parent
SHARED_DIR = UI_DIR / "shared"

sys.path.insert(0, str(SHARED_DIR))
import site_analyzer  # shared, generic -- identical for every test case

TEST_CASES = {
    "jailbreaking": {
        "label": "Test Case 1: Jailbreaking",
        "skill_dir": IEM_AIS_ROOT / "Jailbreaking" / ".claude" / "skills" / "run-jailbreaking",
        "evidence_dir": IEM_AIS_ROOT / "Jailbreaking" / "evidence" / "adversarial",
    },
    "sensitive_info": {
        "label": "Test Case 2: Sensitive Information",
        "skill_dir": IEM_AIS_ROOT / "SensitiveInformation" / ".claude" / "skills" / "run-sensitive-info",
        "evidence_dir": IEM_AIS_ROOT / "SensitiveInformation" / "evidence" / "adversarial",
    },
    "output_handling": {
        "label": "Test Case 3: Output Handling",
        "skill_dir": IEM_AIS_ROOT / "OutputHandling" / ".claude" / "skills" / "run-output-handling",
        "evidence_dir": IEM_AIS_ROOT / "OutputHandling" / "evidence" / "adversarial",
    },
    "unbounded_consumption": {
        "label": "Test Case 4: Unbounded Consumption",
        "skill_dir": IEM_AIS_ROOT / "UnboundedConsumption" / ".claude" / "skills" / "run-unbounded-consumption",
        "evidence_dir": IEM_AIS_ROOT / "UnboundedConsumption" / "evidence" / "adversarial",
    },
}

_loaded = {}


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _get_test_case_modules(test_case):
    if test_case in _loaded:
        return _loaded[test_case]
    skill_dir = TEST_CASES[test_case]["skill_dir"]

    pg_mod = _load_module(f"{test_case}__prompt_generator", skill_dir / "prompt_generator.py")
    sys.modules["prompt_generator"] = pg_mod  # so this test case's inject.py binds to ITS OWN prompt_generator
    sys.modules["site_analyzer"] = site_analyzer  # keep pointed at the one shared copy
    inj_mod = _load_module(f"{test_case}__inject", skill_dir / "inject.py")

    _loaded[test_case] = {"inject": inj_mod, "prompt_generator": pg_mod}
    return _loaded[test_case]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            html = (UI_DIR / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        self.send_error(404)

    def do_POST(self):
        try:
            payload = self._read_json_body()
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON body"}, 400)
            return

        url = (payload.get("url") or "").strip()
        if not url:
            self._send_json({"error": "Missing 'url'"}, 400)
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url

        if self.path == "/api/analyze":
            try:
                profile = site_analyzer.analyze(url)
            except Exception as e:
                self._send_json({"url": url, "error": str(e), "is_llm_site": False, "endpoints": [], "test_cases": {}}, 200)
                return

            result = dict(profile)
            result["test_cases"] = {}
            if not profile.get("error"):
                for tc_key, tc_cfg in TEST_CASES.items():
                    mods = _get_test_case_modules(tc_key)
                    tc_result = {"label": tc_cfg["label"], "config_needs": None, "prompts": []}
                    if profile["is_llm_site"] and profile["endpoints"]:
                        tc_result["config_needs"] = mods["inject"].describe_config_needs(url, profile)
                        tc_result["prompts"] = mods["prompt_generator"].build_prompts(
                            profile["objective"],
                            {"tool_use_hints": profile["tool_use_hints"], "attachment_hints": profile["attachment_hints"]},
                        )
                    result["test_cases"][tc_key] = tc_result
            self._send_json(result)
            return

        test_case = payload.get("test_case")
        if test_case not in TEST_CASES:
            self._send_json({"error": f"Unknown or missing 'test_case' (expected one of {list(TEST_CASES)})"}, 400)
            return
        mods = _get_test_case_modules(test_case)
        evidence_dir = TEST_CASES[test_case]["evidence_dir"]

        if self.path == "/api/test":
            extra_fields = payload.get("extra_fields") or None
            try:
                evidence = mods["inject"].run_full(url, extra_fields)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
                return
            evidence_dir.mkdir(parents=True, exist_ok=True)
            out_path = evidence_dir / f"{test_case}_batch_{datetime.now().strftime('%y%m%d_%H%M%S')}.json"
            out_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            evidence["_evidence_file"] = str(out_path)
            self._send_json(evidence)
            return

        if self.path == "/api/test_one":
            risk_id = payload.get("risk_id")
            prompt_text = payload.get("prompt")
            if risk_id is None or not prompt_text:
                self._send_json({"error": "Missing 'risk_id' or 'prompt'"}, 400)
                return
            try:
                entry = mods["inject"].run_one(
                    url, risk_id, prompt_text,
                    followup_prompt=payload.get("followup_prompt"),
                    followup_same_session=payload.get("followup_same_session", False),
                    extra_fields=payload.get("extra_fields") or None,
                )
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
                return
            if "error" not in entry or entry.get("sent") is not None:
                evidence_dir.mkdir(parents=True, exist_ok=True)
                out_path = evidence_dir / f"{test_case}_single_{datetime.now().strftime('%y%m%d_%H%M%S')}_risk{risk_id}.json"
                out_path.write_text(json.dumps(entry, indent=2), encoding="utf-8")
                entry["_evidence_file"] = str(out_path)
            self._send_json(entry)
            return

        self.send_error(404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"IEM-AIS shared UI running at http://localhost:{args.port}/  ({len(TEST_CASES)} test cases: {', '.join(TEST_CASES)})")
    print("Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
