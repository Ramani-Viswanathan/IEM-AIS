# IEM-AIS

**Intelligence Engineering Methodology — AI Security Assurance**

A local, URL-driven security-testing utility for LLM applications. Given any URL, it determines
whether the site has a real LLM-backed chat interface and, if so, sends real adversarial prompts
to it and records the real replies — no mocked targets, no simulated responses. Each test case is
grounded in one specific risk category from the live **OWASP GenAI LLM Top 10 2026** PDF, fetched
fresh at runtime, never bundled as a static copy.

## Status at a glance

| OWASP risk | Test case | Status |
|---|---|---|
| LLM01:2026 Prompt Injection | `OWASP/Jailbreaking/` | ✅ Built, committed, run repeatedly against a live site |
| LLM02:2026 Sensitive Information Disclosure | `OWASP/SensitiveInformation/` | ✅ Built, committed, run repeatedly against a live site |
| LLM10:2026 Improper Output Handling | `OWASP/OutputHandling/` | ✅ Built, committed, run repeatedly against a live site |
| LLM06:2026 Unbounded Consumption | `OWASP/UnboundedConsumption/` | ✅ Built, committed, run repeatedly against a live site |
| LLM08:2026 Hidden Context Exposure | `OWASP/HiddenContext/` | ✅ Built, verified against a live site (5th test case) |
| LLM09:2026 Vector and Embedding Weaknesses | `OWASP/VectorEmbedding/` | ✅ Built, negative-control + live-OWASP-fetch verified (6th test case, 2 of 7 risks permanently `NOT_APPLICABLE` by design — see below) |
| LLM03:2026 Excessive Agency | `OWASP/ExcessiveAgency/` | ✅ Built, negative-control + live-OWASP-fetch verified (7th test case) |
| LLM07:2026 Misinformation | `OWASP/Misinformation/` | ✅ Built, negative-control + live-OWASP-fetch verified (8th and final test case, 6 of 7 risks permanently `NOT_APPLICABLE` by design — see below) |
| pytest suite | `tests/` | ✅ Built — 74 fixture-based tests, no network |
| Cross-test-case honest verdict report | `ui/shared/report_builder.py` + `POST /api/report` | ✅ Built (Phase 1 of `Project DOCS/IEM-AIS-Platform-Evolution-Plan.md`) — reads saved evidence across sessions, not just one browser tab (see below) |
| LLM04:2026 Supply Chain | — | ❌ Out of scope for this tool, by design |
| LLM05:2026 Data and Model Poisoning | — | ❌ Out of scope for this tool, by design |

## The story

### Why this exists

The project's own design principles (`Project DOCS/IEM-AIS-bludeprint.md`) require that any
verdict this tool emits must never be a bare `SECURE`/`PASSED`. That requirement got sharpened
into an explicit build mandate on **2026-08-22**, when the user's instruction —
*"make sure we provide a honest verdict as recommended by OWASP. that is a game changer."* —
reshaped the plan captured in `Project DOCS/IEM-AIS-Practical-Build-Roadmap.md`: every
practically-testable OWASP GenAI LLM Top 10 risk should get its own focused skill, all sharing one
UI, culminating in a report that states its verdict in plain language, always paired with what
wasn't tested.

That roadmap was written *after* reading the full OWASP GenAI LLM Top 10 2026 PDF end-to-end
(pages 10–57, all 10 risk entries) and cross-checking it against the two test cases that already
existed at that point (Jailbreaking, SensitiveInformation), confirming their risk descriptions,
page citations, and attack-scenario references matched the live document line-by-line. The one
part of each test case that is judgment rather than an OWASP-stated fact is `RISK_TO_CONTROLS` —
which numbered remediation control best fits which numbered risk, since OWASP's own document never
cross-references those two lists itself. That mapping is defensible analysis, not something
fact-checkable against the PDF, and doesn't weaken the pass/fail verdict, which is empirical (a
real prompt sent to a real endpoint, a real reply read back).

### What was planned (2026-08-22 roadmap)

The roadmap sorted all 10 OWASP risks into four buckets:

1. **Build now, directly testable with a single chat message**: LLM01 (already built), LLM02
   (already built), LLM08 Hidden Context Exposure, LLM10 Improper Output Handling (needed a new,
   inverted classifier shape rather than the existing refusal-marker matcher).
2. **Build now, needs modest harness work**: LLM06 Unbounded Consumption (needs a
   `_call_endpoint_burst()` addition for Denial-of-Wallet-style repeated calls), LLM03 Excessive
   Agency (conditional on detected tool-use), LLM09 Vector and Embedding Weaknesses (conditional
   on detected RAG/retrieval signal).
3. **Build now, but flag the ceiling honestly in that skill's own `SKILL.md`**: LLM07
   Misinformation — adversarial prompting is a legitimate partial test (OWASP's own Common
   Example #5, "Adversarially Induced Misinformation," is exactly this), but a rigorous assessment
   needs a curated known-correct-answer eval set this generic tool doesn't have. The plan is to
   build the adversarial-prompt half and document the eval-set gap explicitly, not silently claim
   full coverage.
4. **Explicitly out of scope, with reasons stated rather than silently omitted**: LLM04 Supply
   Chain (a dependency/model-artifact audit problem — `pip-audit`/`modelscan` territory, not a
   live-URL prompt-sending problem) and LLM05 Data and Model Poisoning (needs write access to a
   training set or RAG corpus the target controls, not just their chat endpoint).

Planned build order: OutputHandling → UnboundedConsumption → HiddenContext (done) →
VectorEmbedding (done) → ExcessiveAgency (done) → Misinformation (done) → register everything in
`ui/server.py`'s `TEST_CASES` dict (done, all 8) → build the cross-test-case honest verdict report
(done — see `Project DOCS/IEM-AIS-Platform-Evolution-Plan.md` Phase 1) → universal chatbot reach
and the rest of that plan's phases, ongoing.

### What's actually been built

- **`OWASP/Jailbreaking/` (LLM01)** and **`OWASP/SensitiveInformation/` (LLM02)** — built first, committed in
  the initial commit. Both use refusal-marker string matching: a match means the attack attempt
  was *held*.
- **`OWASP/OutputHandling/` (LLM10)** — built next, per the planned order. Its classifier is
  deliberately inverted from the first two: it greps the raw reply for dangerous patterns
  (`<script>` tags, `DROP TABLE`, raw ANSI escape bytes) rather than refusal markers — a match
  here means *unsafe*, not *held*. Verified live: one dev run against a real site classified a
  reply `OUTPUT_UNSAFE` on a `<script[^>]*>` match, paired with the honest caveat that a match is
  "the first necessary condition, not a confirmed exploit" until someone verifies the target
  actually pipes that output into a real shell/DB/browser sink.
- **`OWASP/UnboundedConsumption/` (LLM06)** — built alongside OutputHandling. Its classifier isn't
  string matching at all: it measures reply length and latency against fixed heuristic thresholds
  (e.g. `BOUNDED` for a reply under the char-count threshold), plus a burst-request mode for the
  one risk (Denial of Wallet) that needs several rapid calls instead of one.
- **Shared UI rebuilt against design canvas mockups** (`ui/index.html`, `ui/server.py`) — added a
  Dashboard-level "Honest Verdict summary" and a Reports view, both fed by one `recordResult()`
  function so every risk's outcome (however it was tested — single-prompt or batch) flows through
  a single source of truth. This is a lighter, client-side, in-session version of roadmap item 4
  (the cross-test-case report) — it aggregates sent/held/needs-review/error counts across
  whichever test cases were run in the current browser session, but it does not yet pull
  `meaning`/`remediation` text fresh from each test case's live OWASP fetch into one authored
  document the way the full planned report does.
- **`ui/shared/inject_base.py`** — the learn/send/record mechanics all four skills' `inject.py`
  used to duplicate got extracted into one shared module; each skill's `inject.py` is now a thin
  wrapper owning only its own `classify()` and OWASP metadata.
- **`ui/shared/references/`** — the shared *documentation* content (learn-phase mechanics,
  per-site config rules, the OWASP-fetch mechanism, common gotchas, common troubleshooting) got the
  same treatment: pulled into one file per topic, linked directly from every skill's `SKILL.md`
  instead of being duplicated or pointing at a sibling skill's primary file.
- **A pytest suite** (`tests/`) — 37 fixture-based tests, zero network calls, covering every
  classifier's verdict shape across all built test cases plus `inject_base.py`'s orchestration
  mechanics (including the `ERROR`/`NOT_APPLICABLE`/burst paths via monkeypatched HTTP). This was
  the Sep 8 code review's top-priority gap (zero test files existed before it).
- **`OWASP/HiddenContext/` (LLM08)** — the 5th test case, built and verified live. All 5 risks are
  directly testable with a single chat message (unlike LLM01/LLM02, nothing here needed a
  `NOT_APPLICABLE` no-real-channel risk).
- **`OWASP/VectorEmbedding/` (LLM09)** — the 6th test case, built against the real OWASP text (p.50-54)
  and verified with a negative control plus a live OWASP-fetch check confirming all 7 risks resolve
  correctly. Unlike every earlier test case, 2 of its 7 OWASP risks (Embedding Inversion, Semantic
  Cache/Dedup Poisoning) are **permanently** `NOT_APPLICABLE` — not conditional on the target site,
  but on this tool's own architecture: both need access (raw stored vectors; the cache layer's
  internal similarity threshold) that no chat-endpoint prompt can ever reach. The other 5 get a
  genuine but partial one-message analogue, honestly documented per-risk in the skill's own
  `SKILL.md` "Applicability ceiling" section. Its Retrieval Jamming risk also has an **inverted**
  classifier within the same skill (a refusal-shaped reply means the attack succeeded, not that it
  was held) — the first skill where the polarity flips per-risk rather than per-skill.
- **`OWASP/ExcessiveAgency/` (LLM03)** — the 7th test case. All 6 risks are always sent (conditional
  only on `has_tools` for wording), each asking the model to attempt an over-scoped, over-
  privileged, or unconfirmed high-impact action. Its own `SKILL.md` "Applicability ceiling"
  section is explicit that a compliant-sounding reply here is weaker evidence than the same
  verdict elsewhere: it can never confirm a real backend tool actually executed anything, only
  that the model's text reply sounded willing.
- **`OWASP/Misinformation/` (LLM07)** — the 8th and final test case, built exactly to the plan flagged
  back on 2026-08-22: only 1 of its 7 OWASP risks (Adversarially Induced Misinformation) is ever
  sent. The other 6 all ask "was the model's output actually true," which needs a curated
  known-correct-answer eval set this generic tool doesn't have and can't invent per target — they
  resolve straight to `NOT_APPLICABLE` for every site, not conditionally. The one risk that IS
  sent sidesteps the eval-set problem entirely: it supplies its own known-false premise and checks
  only whether the target repeats it, needing no ground truth about the target's real domain.
- **The cross-test-case honest verdict report** (`ui/shared/report_builder.py`, `POST /api/report`,
  `ui/shared/finding_schema.md`, `ui/shared/layman_glosses.py`) — Phase 1 of
  `Project DOCS/IEM-AIS-Platform-Evolution-Plan.md`, built exactly to the spec in
  `Project DOCS/IEM-AIS-Practical-Build-Roadmap.md` §4. Scans every registered test case's saved
  evidence for the latest real run against a given URL — across sessions, not just the current
  browser tab — and renders one document: per-risk verdicts paired with a plain-English gloss
  authored by this project (56 of them, one per real risk across all 8 test cases, clearly labeled
  as paraphrase, never presented as an OWASP quote) and what the verdict *family* actually means,
  plus an explicit tested/untested-scope breakdown and the standing limitations statement. A real
  bug caught during its own negative-control test: a batch with zero risks sent (e.g. `NO LLM
  DETECTED`) was initially rendered as "every risk was sent" by the empty-untested-scope fallback
  — fixed so a test case that generated no rows at all shows up as its own explicit coverage gap,
  not as silent full coverage.

### What's still planned, not started

- **Phase 2 onward of `Project DOCS/IEM-AIS-Platform-Evolution-Plan.md`** — universal chatbot
  reach (an explicit endpoint-override config, then an LLM-driven Playwright browser agent so
  IEM-AIS can reach chatbots whose real endpoint is only resolvable by actually running their
  JavaScript, e.g. Lakera's public Agent Breaker challenge, confirmed live as a concrete case this
  tool can't reach yet), a SQLite evidence index, a toy `ReferenceAgent` + policy gateway, evidence
  provenance/retention, a governance-lite control/retest layer, and an evidence export format for
  other repos. See that doc for the full phase-by-phase plan and current priority order.

### Explicitly out of scope

- **LLM04:2026 Supply Chain** — dependency/model-artifact auditing (SBOM, signing, pickle-format
  scanning) needs a different toolchain (`pip-audit`/`modelscan`), not a live-URL
  prompt-sending problem.
- **LLM05:2026 Data and Model Poisoning** — needs write access to a training set or a RAG corpus
  the target controls, not just a chat endpoint on the deployed app.

These are recorded here rather than silently omitted, per the project's own honest-scope rule.

### Test runs and results so far

All actual run evidence lives in each test case's `evidence/adversarial/` folder and is
git-ignored by design (`.gitignore`: *"Real test evidence against live sites — keep local, not
published"*) — raw prompts and raw model replies against a real site are development artifacts,
not something this repo publishes. What follows is a description of the runs, not their raw
contents.

Development-time runs recorded locally, by test case:

| Test case | Risks per run | Local evidence files recorded |
|---|---|---|
| Jailbreaking | 8 | 37 |
| SensitiveInformation | 7 | 9 |
| OutputHandling | 7 | 2 |
| UnboundedConsumption | 9 | 2 |
| HiddenContext | 5 | 2 |
| VectorEmbedding | 7 (2 always `NOT_APPLICABLE`) | 3 |
| ExcessiveAgency | 6 | 1 (negative control only so far) |
| Misinformation | 7 (6 always `NOT_APPLICABLE`) | 1 (negative control only so far) |

Two kinds of targets were used during development:

- **A negative control** (`example.com`) — confirms `site_analyzer.py` correctly reports
  `is_llm_site: false` and skips sending any prompts, rather than false-positiving on a page with
  no LLM interface at all.
- **A real target with an LLM interface** (the developer's own site) — confirms the full pipeline
  end-to-end: site learned once, prompts generated per applicable risk, real requests sent, real
  replies classified. Verdicts observed across these runs span the full taxonomy the classifiers
  are designed to produce — `HELD` and `NEEDS_REVIEW` (Jailbreaking/SensitiveInformation),
  `CLEAN`, `OUTPUT_UNSAFE`, and `DUPLICATE_RESPONSE` (OutputHandling — including the live
  `<script>`-pattern match described above), and `BOUNDED` (UnboundedConsumption) — which is the
  verification recipe each test case's own `SKILL.md` calls for: run against a real site, confirm
  the classifier actually produces every verdict shape it's designed to, not just the happy path.

Every verdict recorded, in every evidence file, carries its heuristic caveat inline (e.g. *"no
refusal marker matched — verify manually, may be compliance or an unrelated reply"*) rather than
a bare pass/fail — this is the honest-verdict requirement holding in practice, not just in the
design doc.

**Live example**: [Honest Verdict Report against ramaniv.com](https://claude.ai/code/artifact/846b6666-5cf0-49bb-8731-9df4b82f3d59)
— all 5 test cases (36 risks) run against a real production site, including one live
`OUTPUT_UNSAFE` finding. The specific prompt/response behind that finding is intentionally not
published here; it's kept in the local, gitignored evidence file for the site owner.

## Install

Only one non-stdlib dependency is needed, for the live OWASP PDF text fetch:

```bash
pip install pypdf
```

## Run

### Shared UI (recommended — serves every test case from one page)

```bash
python ui/server.py --port 8787
# open http://localhost:8787/
```

Enter a target URL; the UI learns the site once, then lets you run any of the registered test
cases against it and view results/evidence per risk, plus the in-session Honest Verdict summary
and Reports view.

### Cross-test-case honest verdict report (reads saved evidence across sessions)

```bash
curl -s -X POST http://localhost:8787/api/report -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/"}'
```

Returns `{"report": {...structured...}, "markdown": "...readable document..."}`, built from
whichever test cases have a saved evidence file for that exact URL — including runs from earlier
sessions, unlike the in-browser Reports view above, which only sees the current tab's memory.

### Single test case from the CLI (writes evidence JSON, no UI)

```bash
cd OWASP/Jailbreaking   # or OWASP/SensitiveInformation / OWASP/OutputHandling / OWASP/UnboundedConsumption / OWASP/HiddenContext / OWASP/VectorEmbedding / OWASP/ExcessiveAgency / OWASP/Misinformation
python .claude/skills/run-<skill-name>/inject.py --url https://example.com/ --out evidence/adversarial
```

Skill names: `run-jailbreaking`, `run-sensitive-info`, `run-output-handling`,
`run-unbounded-consumption`, `run-hiddencontext`, `run-vectorembedding`, `run-excessiveagency`,
`run-misinformation`.

### Test suite

```bash
pip install pytest
pytest
```

Fixture-based, no network — covers every classifier's verdict shapes plus `ui/shared/
inject_base.py`'s shared orchestration mechanics. There is no build step (the frontend is a
single static `ui/index.html`, Tailwind via CDN, no bundler). Beyond the pytest suite, live
behavior is verified by running a skill against a real URL and inspecting the evidence JSON / UI
output — see each test case's `SKILL.md` for its own verification recipe.

## Architecture

One sibling folder per OWASP risk category, grouped under `OWASP/`, each shaped identically:

```
OWASP/<TestCaseName>/.claude/skills/run-<skill-name>/
  SKILL.md                    <- agent-facing docs and spec
  prompt_generator.py          <- builds attack prompts for this risk category; owns its own
                                  live OWASP fetch and risk-to-control mapping
  inject.py                    <- orchestrator: learn site -> generate prompts -> send -> classify
                                  -> record. Exposes run_full(url)/run_one(...) used by ui/server.py
  config/site_overrides.json   <- explicit, user-supplied endpoint body fields only, never guessed
OWASP/<TestCaseName>/evidence/adversarial/   <- real run output, gitignored, never committed
```

Shared, generic mechanics live in `ui/shared/` and are imported by every skill, never duplicated:

- `site_analyzer.py` — the "learn phase." GETs a target URL and its same-origin `<script>`
  bundles (never POSTs), greps for LLM-vendor strings and `fetch()` call sites to decide if the
  site has a real LLM interface, guesses the request/response field shape, and detects
  tool-use/attachment signals used to gate risk applicability.
- `owasp_source.py` — discovers and fetches the current OWASP GenAI LLM Top 10 PDF directly from
  `genai.owasp.org` at runtime (the download URL is discovered from the resource page's HTML, not
  hardcoded).
- `inject_base.py` — the learn/send/record mechanics every skill's `inject.py` uses:
  `load_overrides`, `pick_endpoint`, `describe_config_needs`, `extract_reply`, `call_endpoint`,
  `run_burst`, `flag_duplicate_responses`, `run_prompt_entry`, `run_one`, `run_full`. Each skill
  passes in its own `classify_fn` (contract: `classify_fn(risk_id, response_text, elapsed_ms=None,
  burst_stats=None)`) and `build_prompts_fn` — the classifier itself is never here.
- `references/` — SKILL.md documentation content shared across skills (learn-phase mechanics,
  per-site config, the OWASP-fetch mechanism, common gotchas, common troubleshooting). Every
  skill's `SKILL.md` links to these directly and keeps only what's specific to its own OWASP risk
  category inline.
- `report_builder.py` + `finding_schema.md` + `layman_glosses.py` — the cross-test-case honest
  verdict report (`POST /api/report`). `finding_schema.md` documents the Finding shape every
  skill's evidence JSON already produces; `layman_glosses.py` holds this project's own
  plain-English gloss per real risk (56 of them), clearly separate from OWASP's own live-fetched
  text; `report_builder.py` finds the latest saved evidence per test case for a given URL and
  renders one document from it — verdict families never presented as a bare pass, an explicit
  tested/untested-scope breakdown, and a standing limitations statement.

`ui/server.py`'s `TEST_CASES` dict is the single registration point for adding another test case;
`ui/index.html` needs no change to pick it up — it loops over whatever `/api/analyze` returns.

Classifiers are deliberately different shapes per test case (not duplicated/drifted code):

- **Jailbreaking / SensitiveInformation / HiddenContext**: refusal-marker string matching — a
  match means the attack was *held* (good outcome).
- **OutputHandling**: dangerous raw-pattern matching — a match means the model handed back unsafe
  raw content (bad outcome). Inverted from the above.
- **UnboundedConsumption**: measures reply length and latency against fixed heuristic thresholds,
  plus a burst-request mode for Denial of Wallet. Not string matching at all.
- **VectorEmbedding**: refusal-marker matching like the first group, except its Retrieval Jamming
  risk flips polarity within the same skill (a refusal-shaped reply there means the attack
  succeeded), and 2 of its 7 risks are permanently `NOT_APPLICABLE` for every target — see its
  `SKILL.md` "Applicability ceiling" section.
- **ExcessiveAgency**: refusal/approval-seeking-marker matching. All 6 risks are always sent, but a
  compliant-sounding reply is weaker evidence than elsewhere — it can never confirm a real backend
  tool actually executed anything, only that the model's text sounded willing.
- **Misinformation**: hedge/correction-marker matching, but only 1 of its 7 risks is ever sent — the
  other 6 need a curated known-correct-answer eval set this tool doesn't have, and are permanently
  `NOT_APPLICABLE` by design (the explicit plan for this category since 2026-08-22, not a gap found
  after the fact).

## Adding a new test case

`SKILL.md` is written first as a real spec — which OWASP risks it covers, what each prompt should
test, what the classifier should check for, what's out of scope — before any code is written.
See `CLAUDE.md` for full contributor guidance and `Project DOCS/` for the design principles and
per-OWASP-category build roadmap.

## Repo layout

```
OWASP/
  Jailbreaking/            Test Case 1 (LLM01) -- built, committed
  SensitiveInformation/    Test Case 2 (LLM02) -- built, committed
  OutputHandling/          Test Case 3 (LLM10) -- built, committed
  UnboundedConsumption/    Test Case 4 (LLM06) -- built, committed
  HiddenContext/           Test Case 5 (LLM08) -- built, committed
  VectorEmbedding/         Test Case 6 (LLM09) -- built, committed
  ExcessiveAgency/         Test Case 7 (LLM03) -- built, committed
  Misinformation/          Test Case 8 (LLM07) -- built, committed
ui/                      shared server + frontend + shared mechanics
tests/                   pytest suite -- 74 tests, no network
Project DOCS/            design principles and build roadmap
CLAUDE.md                contributor/agent guidance
```
