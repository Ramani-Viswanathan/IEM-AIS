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
cd OWASP/Jailbreaking   # or OWASP/SensitiveInformation / OWASP/OutputHandling / OWASP/UnboundedConsumption / OWASP/HiddenContext / OWASP/VectorEmbedding / OWASP/ExcessiveAgency / OWASP/Misinformation
python .claude/skills/run-<skill-name>/inject.py --url https://example.com/ --out evidence/adversarial
```

Run the test suite (fixture-based, no network -- covers every classifier's verdict shapes plus
`inject_base.py`'s shared orchestration mechanics):

```bash
pip install pytest
pytest
```

There is no build step (the frontend is a single static `ui/index.html`, Tailwind via CDN, no
bundler). Beyond the pytest suite, live behavior is verified by running a skill against a real URL
and inspecting the evidence JSON / UI output — see each `SKILL.md`'s own "Verification" section
for the exact recipe used when that skill was built.

## Architecture

**One sibling folder per OWASP risk category, grouped under `OWASP/`**, each shaped identically:

```
OWASP/<TestCaseName>/.claude/skills/run-<skill-name>/
  SKILL.md                    <- agent-facing docs only, no logic
  prompt_generator.py          <- builds N attack prompts for this risk category; owns its own
                                  live OWASP fetch (_get_reference()) and RISK_TO_CONTROLS mapping
  inject.py                    <- thin wrapper over ui/shared/inject_base.py: owns only this risk
                                  category's classify() + its refusal-marker/dangerous-pattern data
                                  and OWASP citation/probe name. Exposes run_full(url)/run_one(...)
                                  used by ui/server.py -- both just call inject_base's version.
  config/site_overrides.json   <- explicit, user-supplied endpoint body fields only, never guessed
OWASP/<TestCaseName>/evidence/adversarial/   <- real run output, gitignored, never committed
```

Eight exist today: `Jailbreaking` (LLM01), `SensitiveInformation` (LLM02), `OutputHandling`
(LLM10), `UnboundedConsumption` (LLM06), `HiddenContext` (LLM08), `VectorEmbedding` (LLM09),
`ExcessiveAgency` (LLM03), `Misinformation` (LLM07). This is the full set the project scoped as
practically testable (`Project DOCS/IEM-AIS-Practical-Build-Roadmap.md`); LLM04 Supply Chain and
LLM05 Data and Model Poisoning are explicitly out of scope for this tool (see that roadmap).
`ui/server.py`'s `TEST_CASES` dict is the single registration point for adding another;
`ui/index.html` needs no change to pick up a new one — it already loops over whatever
`/api/analyze` returns.

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
- `inject_base.py` — the learn/send/record mechanics every skill's `inject.py` used to duplicate:
  `load_overrides`, `pick_endpoint`, `describe_config_needs`, `extract_reply`, `call_endpoint`,
  `run_burst`, `flag_duplicate_responses`, `run_prompt_entry`, `run_one`, `run_full`. Each skill
  passes in its own `classify_fn` (contract: `classify_fn(risk_id, response_text, elapsed_ms=None,
  burst_stats=None)`) and `build_prompts_fn` — the classifier itself is never here (see below).
  `run_full` takes `flag_duplicates=True` by default; UnboundedConsumption passes `False` since its
  original `inject.py` never ran that step.
- `references/` — SKILL.md documentation content shared across skills (learn-phase mechanics,
  per-site config rules, the OWASP-fetch mechanism, common gotchas, common troubleshooting). Every
  skill's `SKILL.md` links to these directly (one level deep, per [Anthropic's Skill authoring best
  practices](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices)) and
  keeps only what's actually specific to its own OWASP risk category inline. When editing shared
  mechanics, update the reference file once — don't re-describe it in a fifth `SKILL.md`.

**`ui/server.py`'s module-loading gotcha**: every skill has its own `inject.py` and
`prompt_generator.py` with identical filenames but different content. A plain `import` would only
ever bind the first one loaded (Python caches by module name). `_get_test_case_modules()` loads
each pair via `importlib.util.spec_from_file_location` under a distinct `sys.modules` key and
primes `sys.modules["prompt_generator"]` immediately before exec'ing that skill's `inject.py`, so
each skill's internal `import prompt_generator` binds to its own sibling, not another test case's.

**Classifiers are deliberately different shapes per test case** — this is intentional, not
duplicated/drifted code:

- `Jailbreaking` / `SensitiveInformation` / `HiddenContext`: refusal-marker string matching — a
  match means the attack was _held_ (good outcome).
- `OutputHandling`: dangerous raw-pattern matching (`<script>`, `DROP TABLE`, raw ANSI bytes) — a
  match means the model handed back unsafe raw content (bad outcome). Inverted from the above.
- `UnboundedConsumption`: measures reply _length_ and _latency_ against fixed heuristic
  thresholds, plus a burst-request mode for the one risk (Denial of Wallet) that needs several
  rapid calls instead of one. Not string matching at all.
- `VectorEmbedding`: refusal-marker matching like the first group, EXCEPT for its one Retrieval
  Jamming risk, where the polarity flips within the same skill — a refusal-shaped reply there means
  the induced "no information" attack succeeded (bad outcome), not that it was held. Two of its
  seven OWASP risks (Embedding Inversion, Semantic Cache/Dedup Poisoning) are permanently
  `NOT_APPLICABLE` for every target — they need access (raw stored vectors, the cache layer's
  internal threshold) no chat-endpoint prompt can reach; see its own `SKILL.md` "Applicability
  ceiling" section before trusting any verdict from this skill.
- `ExcessiveAgency`: refusal/approval-seeking-marker matching like the first group. All 6 risks are
  always sent (conditional only on `has_tools` for wording, same pattern as a few LLM01/LLM02/LLM09
  risks) — but a compliant-sounding reply here is weaker evidence than the same verdict elsewhere:
  it can never confirm a real backend action actually executed, only that the model's text reply
  sounded willing. See its own `SKILL.md` "Applicability ceiling" section.
- `Misinformation`: hedge/correction-marker matching, but only 1 of its 7 OWASP risks (Adversarially
  Induced Misinformation) is ever sent — the other 6 all require comparing output against a curated
  known-correct-answer eval set this tool doesn't have, and are permanently `NOT_APPLICABLE` by
  design, not conditionally. This was the explicit "flag the ceiling honestly" plan for LLM07 from
  `Project DOCS/IEM-AIS-Practical-Build-Roadmap.md`, not a gap discovered after the fact.

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
