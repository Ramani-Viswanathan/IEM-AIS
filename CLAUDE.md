# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

IEM-AIS (Intelligence Engineering Methodology — AI Security Assurance) is a local, URL-driven
security-testing utility for LLM applications. Given any URL, it determines whether the site has
a real LLM-backed chat interface and, if so, sends real adversarial prompts to it and records the
real replies — no mocked targets, no simulated responses. Each test case is grounded in one
specific risk category from the live **OWASP GenAI LLM Top 10 2026** PDF, fetched fresh at
runtime, never bundled as a static copy.

## Commands

Install the one non-stdlib dependency (only needed for the live OWASP PDF text fetch):

```bash
pip install pypdf
```

Run the shared UI (serves every test case from one page):

```bash
python ui/server.py --port 8787
# open http://localhost:8787/
```

Run a single test case from the CLI (writes evidence JSON, no UI):

```bash
cd Jailbreaking   # or SensitiveInformation / OutputHandling / UnboundedConsumption
python .claude/skills/run-<skill-name>/inject.py --url https://example.com/ --out evidence/adversarial
```

There is no build step (the frontend is a single static `ui/index.html`, Tailwind via CDN, no
bundler) and no automated test suite. Verification is done by running a skill live against a real
URL and inspecting the evidence JSON / UI output — see each `SKILL.md`'s own "Verification"
section for the exact recipe used when that skill was built.

## Architecture

**One sibling folder per OWASP risk category**, each shaped identically:

```
<TestCaseName>/.claude/skills/run-<skill-name>/
  SKILL.md                    <- agent-facing docs only, no logic
  prompt_generator.py          <- builds N attack prompts for this risk category; owns its own
                                  live OWASP fetch (_get_reference()) and RISK_TO_CONTROLS mapping
  inject.py                    <- orchestrator: learn site -> generate prompts -> send -> classify
                                  -> record. Exposes run_full(url)/run_one(...) used by ui/server.py
  config/site_overrides.json   <- explicit, user-supplied endpoint body fields only, never guessed
<TestCaseName>/evidence/adversarial/   <- real run output, gitignored, never committed
```

Four exist today: `Jailbreaking` (LLM01), `SensitiveInformation` (LLM02), `OutputHandling`
(LLM10), `UnboundedConsumption` (LLM06). `ui/server.py`'s `TEST_CASES` dict is the single
registration point for adding another; `ui/index.html` needs no change to pick up a new one — it
already loops over whatever `/api/analyze` returns.

**Shared, generic mechanics live in `ui/shared/`** and are imported by every skill, never
duplicated:

- `site_analyzer.py` — the "learn phase." GETs a target URL and its same-origin `<script>`
  bundles (never POSTs), greps for LLM-vendor strings and `fetch()` call sites to decide if the
  site has a real LLM interface, guesses the request/response field shape, and detects
  tool-use/attachment signals used to gate risk applicability.
- `owasp_source.py` — discovers and fetches the current OWASP GenAI LLM Top 10 PDF directly from
  `genai.owasp.org` at runtime (the download URL itself is discovered from the resource page's
  HTML, not hardcoded). `find_entry_section()` guards against the PDF's table of contents (which
  repeats every heading) by requiring a `confirm_near` string shortly after the real match.

**`ui/server.py`'s module-loading gotcha**: every skill has its own `inject.py` and
`prompt_generator.py` with identical filenames but different content. A plain `import` would only
ever bind the first one loaded (Python caches by module name). `_get_test_case_modules()` loads
each pair via `importlib.util.spec_from_file_location` under a distinct `sys.modules` key and
primes `sys.modules["prompt_generator"]` immediately before exec'ing that skill's `inject.py`, so
each skill's internal `import prompt_generator` binds to its own sibling, not another test case's.

**Classifiers are deliberately different shapes per test case** — this is intentional, not
duplicated/drifted code:

- `Jailbreaking` / `SensitiveInformation`: refusal-marker string matching — a match means the
  attack was _held_ (good outcome).
- `OutputHandling`: dangerous raw-pattern matching (`<script>`, `DROP TABLE`, raw ANSI bytes) — a
  match means the model handed back unsafe raw content (bad outcome). Inverted from the above.
- `UnboundedConsumption`: measures reply _length_ and _latency_ against fixed heuristic
  thresholds, plus a burst-request mode for the one risk (Denial of Wallet) that needs several
  rapid calls instead of one. Not string matching at all.

**Honest-verdict requirement — applies to every future test case, not optional polish**: this
tool must never emit a bare `SECURE`/`PASSED`. Every verdict states what was tested, what wasn't,
and that it's a heuristic requiring manual verification, never a guarantee. This is grounded in
`Project DOCS/IEM-AIS-bludeprint.md` (§10 Rule #10: "a failed probe is not automatically proof of
absence of a vulnerability"; §15: a score is "not a guarantee of security") and in OWASP LLM01's
own control #11 (static attack-success claims must be rejected; adaptive attacks succeed far more
often than single-shot ones). `Project DOCS/IEM-AIS-Practical-Build-Roadmap.md` has the full
per-OWASP-category feasibility analysis and build order for test cases not yet built.

Note: `Project DOCS/IEM-AIS-bludeprint.md` §17 sketches a larger, more abstract architecture
(`iem_ais/core/`, `probes/`, a manifest/scoring engine) that was the original design vision. The
actual implementation diverged to the simpler sibling-skill-folder pattern described above — treat
the blueprint as the source of the project's _principles_ (honest verdicts, evidence requirements,
security domain taxonomy), not as a literal file/folder spec to reconcile with.

## How new test cases get built

As of this session, `SKILL.md` authorship has shifted: for test cases built going forward, the
user writes `SKILL.md` **first**, as a real spec (which OWASP risks it covers, what each prompt
should test, what the classifier should check for, what's explicitly out of scope, conditional vs.
always-applicable risks) — Claude builds `prompt_generator.py`/`inject.py` against it, and flags
gaps in the spec back to the user rather than silently resolving them. For the four existing test
cases, `SKILL.md` was written after the code, as documentation — don't take those four as the
template for how a fifth should be authored.
