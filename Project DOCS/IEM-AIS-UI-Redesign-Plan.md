# IEM-AIS UI Redesign Plan
## Rebuilding ui/index.html against Ramani's design canvas mockups
### Saved 2026-08-24 — design change only, no backend/logic change

## Post-ship fixes & additions (activity log)

- [x] **Assessment buried in collapsed details** — the "this run: HELD/..." interpretation was
  nested inside the collapsed `OWASP Reference & Remediation` `<details>` block instead of sitting
  right under the response. Moved out into its own colored callout box directly after the response
  text; `<details>` now holds only the OWASP quote + remediation list. (`assessmentBox()`,
  `referenceBlockHtml()`, `renderRiskCards()`)
- [x] **Reports view stayed empty** — root cause: the report's data cache (`evidenceByTc`) was
  only ever written by the batch `runTest()` path. Every test run via individual "Test this prompt"
  clicks (`testOne()`) never populated it. Replaced with `testResultsByTc`/`metaByTc`, fed by BOTH
  `testOne()` and the batch path via a shared `recordResult()` helper, so single-prompt tests now
  show up in Reports too. `renderReport()` also now lists every risk the tool *knows* about per
  test case (from `promptMeta`), not just ones already tested — so "not tested this session yet"
  is told apart from "NOT_APPLICABLE (no real channel)" instead of both looking like silence.
- [x] **Dashboard "Honest Verdict" panel never updated** — was only ever set once, at page load /
  reset. Added `updateHonestVerdictSummary()`, called from `recordResult()` after every test
  (single or batch), showing a live held/needs-review/error tally plus a link into the full Report.
- [x] **Export to PDF** — added an "Export to PDF" button on the Reports view using the browser's
  native print (`window.print()`, no new dependency). A dedicated `@media print` stylesheet hides
  all app chrome (sidebar/top bar/other views/the export button itself), forces original colors to
  survive printing (`print-color-adjust: exact`), and compacts spacing/type size to fit a typical
  run on one page. A very large run (many test cases/risks tested) will paginate rather than lose
  content — nothing is truncated, it just spans more than one printed page.

---

## 1. Source of truth

Three design-canvas artboards under `Misc/`, each a `DESIGN.md` (design-system spec) +
`code.html` (Tailwind mockup) + `screen.png`, all sharing one identical design system
(`Objective Security Framework` — Hanken Grotesk/Inter/JetBrains Mono type, a specific
Tailwind color-token set including `verdict-refused`/`verdict-review`/`verdict-active`,
sharp 0.25rem-radius cards, no drop shadows, 1px `border-subtle` outlines):

1. **"Audit Dashboard & Honest Verdict Report"** — landing/dashboard state
2. **"Audit in Progress Prompt Injection Probe"** — a live-testing state
3. **"Consolidated Honest Verdict Report"** — a final report state

Ramani's brief: **"only Design change, not functional or exact logic change"** — restyle,
don't rebuild. When asked how literally to match the mockups' admin-console chrome
(sidebar items like Vulnerability Database, Compliance Docs, System Logs, an "Admin
Console / Security Lead" persona, notifications, logout — none of which have any real
feature behind them today or on the roadmap), his answer: **build what's feasible given
what's actually built and planned, and remember this is a utility app that runs locally
on one person's desktop** — not a multi-user SaaS product. That reframes the mockups'
admin-console/persona/notification chrome as stylistic reference, not a literal spec.

## 2. What stays exactly as-is

Every existing JS function in `ui/index.html`, unchanged in signature and behavior:
`analyze()`, `renderTestCaseSections()`, `renderPromptTable()`, `testOne()`, `runTest()`,
`applyBatchResults()`, `assessmentHtml()`, `verdictClass()`, `collectExtraFields()`,
`renderConfigNeeds()`. Every backend call (`/api/analyze`, `/api/test`, `/api/test_one`)
— same request bodies, same response handling. No changes to `ui/server.py`,
`ui/shared/*.py`, or either skill folder's `inject.py`/`prompt_generator.py`.

## 3. The rebuild: one file, three view-states

Rebuild `ui/index.html` in place: adopt the mockups' Tailwind CDN + `tailwind.config`
token block (copied straight from any of the three `DESIGN.md` frontmatter blocks — byte-
identical across all three), Google Fonts for Hanken Grotesk/Inter/JetBrains Mono, a
persistent left sidebar + minimal top bar. Inside `<main>`, three `<section>` view
containers toggled by a new `showView(name)` function — the one genuinely new piece of
JS, pure presentation state.

**Navigation, trimmed to what's real:** sidebar lists only **Dashboard**, **Live
Testing**, **Reports** — plus **Start New Audit** (resets to Dashboard, clears state,
focuses the URL input). Dropped from the mockups: the "Admin Console / Security Lead"
persona box, notifications bell, account icon, Logout/Help Center, and the sidebar items
with no feature behind them (Vulnerability Database, Compliance Docs, System Logs,
History, Settings). Top bar becomes just the IEM-AIS wordmark — no duplicate nav row.

### View 1 — Dashboard

Hero URL input (mockup's monospace-placeholder, bottom-border style) wired to the
existing `analyze()`. One scenario card per test case, populated from the real
`/api/analyze` response's `test_cases` keys (not the mockup's 4 hardcoded cards) — loops
however many test cases exist, no UI change needed as new skills land. Each card gets a
short 1-line description the API doesn't return today — a small static
`{tcKey: description}` map in the JS, the one place new authored (not fetched) copy is
added, same category as the existing `<div class="intro">` paragraph. Card click routes
to Live Testing for that test case. The existing "config needed" panel lives here,
restyled with the mockup's amber `verdict-review` accent. "The Honest Verdict" panel at
the bottom shows real state: the mockup's own empty-state copy before any run, a short
summary pointing to Reports after one.

### View 2 — Live Testing (extended beyond the mockup)

The mockup doesn't show the one interaction the whole tool is built around — editing a
prompt and testing it individually — so that capability is folded into this view's cards.
Header: test case label, target URL, elapsed-time clock (cosmetic), the existing "Run All
N (batch)" button (`runTest(tcKey)`, unchanged). One card per risk (today's table row →
a card: risk name/citation/applicability note/editable prompt textarea/optional follow-up
textarea/"Test this prompt" button calling the unchanged `testOne(tcKey, riskId)`). Card
border color reflects the real verdict via the existing `verdictClass()` output — a
straight class mapping of data that already exists. Right column keeps a Live Telemetry
terminal-styled panel, fed only from real, client-observable events (request sent,
response received, each risk's real verdict appended once known) — no fabricated
per-card progress percentage, no functional Abort (disabled/labeled honestly — no cancel
capability exists in `inject.py`, and adding one is out of scope here).

### View 3 — Reports

Populated once at least one test case has completed a batch run this session (cache each
`runTest()` response's `evidence` object client-side, keyed by `tcKey`). Stat header
keeps Target URL / Date of Audit / a real computed Probe Coverage % — but swaps the
mockup's "Model Version" stat for "Endpoint Tested" (`evidence.endpoint_used`), since this
tool has no way to know a black-box target's model version. "The Overall Verdict" callout
keeps the mockup's disclaimer language close to verbatim — it already matches OWASP
control #11 / the IEM-AIS blueprint's Rule #10. "Detailed Findings" becomes one row per
**risk** (not per test case), grouped under each test case, reusing the exact
`meaning`/`remediation`/verdict data already computed — column header stays **"OWASP
Reference"**, not the mockup's "Layman Meaning" (a real plain-English paraphrase isn't
built yet — that's separately-approved future work, not part of this design-only pass).
"Tested Scope vs Untested Scope" is computed from real `applicable`/`sent` flags and each
risk's own `applicability_note`, not the mockup's invented example categories.

## 4. Deliberate departures from literal mockup fidelity

| Mockup shows | This build does instead | Why |
|---|---|---|
| "Model Version: LLaMA-3-70B-Instruct" | "Endpoint Tested: /api/chat" | Can't know a black-box target's model version — inventing one breaks the honest-verdict standard. |
| Per-card "RUNNING (65%)" progress bar | Cards stay queued/neutral until the batch response lands, all at once | The backend runs one atomic batch call — no real per-risk progress signal exists to show. |
| Functional "ABORT" button | Disabled, honestly labeled | No cancel capability in `inject.py` today; adding one is a functional change, out of scope. |
| "LAYMAN MEANING" column | "OWASP REFERENCE" column | Content is still OWASP's own quoted text — a real paraphrase isn't built yet. |
| Invented "LLM04/LLM05 excluded" examples | Real `applicability_note` text per untested risk | This tool doesn't test those categories at all yet; citing them by name would overstate scope. |
| Admin Console / Security Lead persona, notifications, logout | Removed | No accounts on a local single-user desktop utility. |

## 5. Files

- `ui/index.html` — full rewrite of markup/CSS/head; every existing script function kept.
- No changes to `ui/server.py`, `ui/shared/*.py`, or either skill's `inject.py`/
  `prompt_generator.py`.

## 6. Verification

`python ui/server.py`, open `http://localhost:8787/`: Dashboard renders scenario cards
for both existing test cases after analyzing a real LLM site; Live Testing still allows
editing + testing a single prompt (`/api/test_one`) and running the full batch
(`/api/test`), producing identical evidence JSON to today; Reports populates only after a
batch run, with a Probe Coverage percentage and Tested/Untested Scope that match the
actual returned evidence. No cross-test-case contamination; evidence still written to
each test case's own `evidence/adversarial/` folder.
