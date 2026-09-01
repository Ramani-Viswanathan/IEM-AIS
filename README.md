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
| LLM01:2026 Prompt Injection | `Jailbreaking/` | ✅ Built, committed, run repeatedly against a live site |
| LLM02:2026 Sensitive Information Disclosure | `SensitiveInformation/` | ✅ Built, committed, run repeatedly against a live site |
| LLM10:2026 Improper Output Handling | `OutputHandling/` | ✅ Built and verified against a live site — **not yet committed to git** |
| LLM06:2026 Unbounded Consumption | `UnboundedConsumption/` | ✅ Built and verified against a live site — **not yet committed to git** |
| LLM08:2026 Hidden Context Exposure | `HiddenContext/` | 📋 Planned, not started |
| LLM03:2026 Excessive Agency | `ExcessiveAgency/` | 📋 Planned, not started |
| LLM09:2026 Vector and Embedding Weaknesses | `VectorEmbedding/` | 📋 Planned, not started |
| LLM07:2026 Misinformation | `Misinformation/` | 📋 Planned, not started (partial-coverage by design — see below) |
| Cross-test-case honest verdict report | `ui/shared/report_builder.py` (planned) | 📋 Not built. A lighter, in-browser version already exists (see below) |
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

Planned build order: OutputHandling → UnboundedConsumption → HiddenContext → ExcessiveAgency /
VectorEmbedding → Misinformation → register everything in `ui/server.py`'s `TEST_CASES` dict →
build the cross-test-case honest verdict report once at least two of the new test cases exist to
design it against real evidence.

### What's actually been built

- **`Jailbreaking/` (LLM01)** and **`SensitiveInformation/` (LLM02)** — built first, committed in
  the initial commit. Both use refusal-marker string matching: a match means the attack attempt
  was *held*.
- **`OutputHandling/` (LLM10)** — built next, per the planned order. Its classifier is
  deliberately inverted from the first two: it greps the raw reply for dangerous patterns
  (`<script>` tags, `DROP TABLE`, raw ANSI escape bytes) rather than refusal markers — a match
  here means *unsafe*, not *held*. Verified live: one dev run against a real site classified a
  reply `OUTPUT_UNSAFE` on a `<script[^>]*>` match, paired with the honest caveat that a match is
  "the first necessary condition, not a confirmed exploit" until someone verifies the target
  actually pipes that output into a real shell/DB/browser sink.
- **`UnboundedConsumption/` (LLM06)** — built alongside OutputHandling. Its classifier isn't
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

**Not yet committed**: `OutputHandling/` and `UnboundedConsumption/` exist and have been run
successfully against a live site, but are still untracked in git, and `ui/server.py`/
`ui/index.html` have uncommitted local changes (the registration and UI work for those two test
cases). They're functionally done; the commit hasn't happened yet.

### What's still planned, not started

- **`HiddenContext/` (LLM08)** — next in the build order. Deliberately overlaps prompts already
  inside LLM01/LLM02 (asking for system prompt/tool schemas) but gets its own focused skill per
  the "every scenario has its own skill" rule rather than being folded into an existing one.
- **`ExcessiveAgency/` (LLM03)** — conditional on `site_analyzer.py`'s existing `has_tools`
  detection, same conditional-risk pattern already used for a couple of LLM01/LLM02 risks.
- **`VectorEmbedding/` (LLM09)** — conditional on a detected RAG/retrieval signal, same honest
  analogue pattern.
- **`Misinformation/` (LLM07)** — adversarial-prompt half only; the eval-set gap gets documented
  in that skill's own `SKILL.md`, not silently glossed over.
- **The full cross-test-case honest verdict report** (`ui/shared/report_builder.py` or a new
  `/api/report` endpoint — exact shape undecided) — per-risk rows pairing OWASP's live-fetched
  text with a plain-English gloss authored by the project (clearly labeled as paraphrase, never
  presented as an OWASP quote), a verdict per risk that's always paired with what the verdict
  label actually means, and an overall summary stating tested scope, untested scope (and why),
  test date, target URL, and a standing limitations statement. Planned to be built once at least
  two of the still-unbuilt test cases exist, so it's designed against real multi-test-case
  evidence rather than a single case.
- Registering the remaining skills in `ui/server.py`'s `TEST_CASES` dict (currently 4 of the
  eventual ~8 testable risk categories are registered).

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

### Single test case from the CLI (writes evidence JSON, no UI)

```bash
cd Jailbreaking   # or SensitiveInformation / OutputHandling / UnboundedConsumption
python .claude/skills/run-<skill-name>/inject.py --url https://example.com/ --out evidence/adversarial
```

Skill names: `run-jailbreaking`, `run-sensitive-info`, `run-output-handling`,
`run-unbounded-consumption`.

There is no build step (the frontend is a single static `ui/index.html`, Tailwind via CDN, no
bundler) and no automated test suite — verification is done by running a skill live against a
real URL and inspecting the evidence JSON / UI output. See each test case's `SKILL.md` for its
own verification recipe.

## Architecture

One sibling folder per OWASP risk category, each shaped identically:

```
<TestCaseName>/.claude/skills/run-<skill-name>/
  SKILL.md                    <- agent-facing docs and spec
  prompt_generator.py          <- builds attack prompts for this risk category; owns its own
                                  live OWASP fetch and risk-to-control mapping
  inject.py                    <- orchestrator: learn site -> generate prompts -> send -> classify
                                  -> record. Exposes run_full(url)/run_one(...) used by ui/server.py
  config/site_overrides.json   <- explicit, user-supplied endpoint body fields only, never guessed
<TestCaseName>/evidence/adversarial/   <- real run output, gitignored, never committed
```

Shared, generic mechanics live in `ui/shared/` and are imported by every skill, never duplicated:

- `site_analyzer.py` — the "learn phase." GETs a target URL and its same-origin `<script>`
  bundles (never POSTs), greps for LLM-vendor strings and `fetch()` call sites to decide if the
  site has a real LLM interface, guesses the request/response field shape, and detects
  tool-use/attachment signals used to gate risk applicability.
- `owasp_source.py` — discovers and fetches the current OWASP GenAI LLM Top 10 PDF directly from
  `genai.owasp.org` at runtime (the download URL is discovered from the resource page's HTML, not
  hardcoded).

`ui/server.py`'s `TEST_CASES` dict is the single registration point for adding another test case;
`ui/index.html` needs no change to pick it up — it loops over whatever `/api/analyze` returns.

Classifiers are deliberately different shapes per test case (not duplicated/drifted code):

- **Jailbreaking / SensitiveInformation**: refusal-marker string matching — a match means the
  attack was *held* (good outcome).
- **OutputHandling**: dangerous raw-pattern matching — a match means the model handed back unsafe
  raw content (bad outcome). Inverted from the above.
- **UnboundedConsumption**: measures reply length and latency against fixed heuristic thresholds,
  plus a burst-request mode for Denial of Wallet. Not string matching at all.

## Adding a new test case

`SKILL.md` is written first as a real spec — which OWASP risks it covers, what each prompt should
test, what the classifier should check for, what's out of scope — before any code is written.
See `CLAUDE.md` for full contributor guidance and `Project DOCS/` for the design principles and
per-OWASP-category build roadmap.

## Repo layout

```
Jailbreaking/            Test Case 1 (LLM01) -- built, committed
SensitiveInformation/    Test Case 2 (LLM02) -- built, committed
OutputHandling/          Test Case 3 (LLM10) -- built, verified, not yet committed
UnboundedConsumption/    Test Case 4 (LLM06) -- built, verified, not yet committed
ui/                      shared server + frontend + shared mechanics
Project DOCS/            design principles and build roadmap
CLAUDE.md                contributor/agent guidance
```
