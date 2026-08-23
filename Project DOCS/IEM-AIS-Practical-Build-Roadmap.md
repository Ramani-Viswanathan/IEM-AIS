# IEM-AIS Practical Build Roadmap
## One focused skill per OWASP scenario, shared UI, honest verdict report
### Saved 2026-08-22 — plan only, build starts next session

---

## 1. Where this comes from

This session, `Misc/OWASP-GenAI-LLM-Top-10-2026-v1.0.pdf` was read end-to-end (all 10 risk
entries, pages 10–57) and cross-checked against the two test cases already built:

- `Jailbreaking/` — LLM01:2026 Prompt Injection, all 8 Common Examples of Risk (p.12–13),
  matched to Example Attack Scenarios (p.15–17)
- `SensitiveInformation/` — LLM02:2026 Sensitive Information Disclosure, all 7 Common
  Examples of Risk (p.19–20), tiered remediation (Foundational/Hardening/Advanced, p.20–21)

Both were verified correct line-by-line against the live PDF text — risk descriptions, page
numbers, and scenario citations all match. The one part of each that is **our judgment, not
an OWASP fact**: `RISK_TO_CONTROLS`, which numbered remediation control best fits which
numbered risk. OWASP's own document never cross-references those two lists itself, so this
mapping is defensible analysis, not something fact-checkable against the PDF. This does
**not** weaken the pass/fail verdict itself — that's empirical (a real prompt sent to the
real endpoint, a real reply read back) — it only affects the "which control to fix first"
recommendation.

Ramani's instruction that reshaped this plan: **"make sure we provide a honest verdict as
recommended by OWASP. that is a game changer."** — plus the scope correction that every
practically-testable OWASP scenario should get its own focused skill, all sharing one UI,
with a final report that states the verdict in plain language. No hardcoding, always fetch
the live PDF. UI design is Ramani's to provide — this roadmap does not touch UI layout.

---

## 2. What "honest verdict, per OWASP" means — not a slogan, pulled from the text

- **LLM01 control #11 (p.15)**: *"reject static-only attack-success claims... Nasr et al.
  (2025) found static attack success near zero while adaptive attack success exceeded 90%
  for most of 12 recent defenses."* A refusal to one scripted prompt is not evidence the app
  is safe against a real attacker who iterates.
- **`Project DOCS/IEM-AIS-bludeprint.md` §10, Rule #10** (already written, pre-dates this
  roadmap): *"A failed probe is not automatically proof of absence of a vulnerability; test
  coverage and limitations must be recorded."* Rule #8: *"Findings must distinguish
  vulnerability from theoretical risk."*
- **Same blueprint, §15**: *"The score is not a guarantee of security... Always display:
  tested scope, untested scope, test date, model/version, configuration, probe coverage,
  limitations."*
- **LLM02 (p.19)**: *"Severity should turn on what the recipient can learn, not on whether
  the leak looked like natural language."*

**What this rules out**: this tool must never emit a bare `SECURE` or `PASSED`. Every verdict
— per-prompt (`HELD` / `NEEDS_REVIEW` / `DUPLICATE_RESPONSE` / `NOT_APPLICABLE` / `ERROR`)
and the new cross-test-case report's overall verdict — reads as *"no compromise observed in
THIS specific test, under THESE specific conditions, on THIS date,"* paired with what was
**not** tested (untested risks, single-shot not adaptive, heuristic detection not human
judgment). An SMB reading the report should not be able to mistake it for a guarantee.

---

## 3. Scope: one folder/skill per practically-testable OWASP scenario

Same pattern as the two existing test cases: own `SKILL.md`, own `prompt_generator.py` (own
live `_get_reference()` fetch, own `RISK_TO_CONTROLS` judgment call, clearly labeled), own
`inject.py`, own `config/site_overrides.json`, own `evidence/adversarial/` — one more entry
in `ui/server.py`'s `TEST_CASES` dict. `ui/index.html` needs no code change; it already loops
over whatever test cases `/api/analyze` returns.

Cross-checking all 10 OWASP categories against "testable by a small team hitting their own
running app, no special infra":

### Build now — directly testable, single chat message
| Risk | Folder (planned) | Notes |
|---|---|---|
| LLM01 Prompt Injection | `Jailbreaking/` | ✅ already built |
| LLM02 Sensitive Information Disclosure | `SensitiveInformation/` | ✅ already built |
| LLM08 Hidden Context Exposure (p.46–49, 5 risks) | `HiddenContext/` | Overlaps prompts already inside LLM01/LLM02 (asking for system prompt/tool schemas), but gets its own focused skill per the "every scenario has its own skill" rule rather than being folded in. |
| LLM10 Improper Output Handling (p.55–57, 7 risks) | `OutputHandling/` | **New classifier shape needed**: pass/fail is "did the raw reply contain unescaped executable content" (SQL keywords, `<script>`, shell metacharacters, raw ANSI bytes) — not refusal-marker matching. `classify()` here is genuinely new logic, not a `REFUSAL_MARKERS` reuse. |

### Build now — testable with modest harness work
| Risk | Folder (planned) | Notes |
|---|---|---|
| LLM06 Unbounded Consumption (p.38–42, 9 risks) | `UnboundedConsumption/` | Most risks are one-prompt testable (variable-length flood, large-context abuse, reasoning-loop bait). A few (repeated-request Denial-of-Wallet, tool-call fan-out) need a small `_call_endpoint_burst()` addition — fires N requests, records latency/size per call. |
| LLM03 Excessive Agency (p.23–26, 6 risks) | `ExcessiveAgency/` | Conditional on detected tool-use (`has_tools`), same pattern already used for LLM01 risks 2/3 and LLM02 risks 3/7. |
| LLM09 Vector and Embedding Weaknesses (p.50–54, 7 risks) | `VectorEmbedding/` | Conditional on detected RAG/retrieval signal, same honest-analogue pattern as existing conditional risks. |

### Build now, but flag the ceiling honestly in that skill's own SKILL.md
| Risk | Folder (planned) | Notes |
|---|---|---|
| LLM07 Misinformation (p.43–45, 7 risks) | `Misinformation/` | Adversarial prompting IS a legitimate partial test (Common Example #5 "Adversarially Induced Misinformation" is exactly this) — but a rigorous assessment needs a curated known-correct-answer eval set this generic tool doesn't have. Build the adversarial-prompt half, document the eval-set gap explicitly. |

### Explicitly out of scope for this tool — state why, don't silently omit
| Risk | Why not this tool |
|---|---|
| LLM04 Supply Chain | Dependency/model-artifact audit (SBOM, signing, pickle-format scanning) — a different toolchain (`pip-audit`/`modelscan`), not a live-URL prompt-sending problem. |
| LLM05 Data and Model Poisoning | Needs write access to a training set or a RAG corpus the SMB controls, not just a chat endpoint on the deployed app. |

### Cross-reference to the pre-existing blueprint

`Project DOCS/IEM-AIS-bludeprint.md` §9 already named 8 probe families (P01–P08), written
before either test case existed. Mapping this roadmap onto it:

- P01/P02 (Prompt Injection / Jailbreak) → `Jailbreaking/` ✅
- P04 (Sensitive Info Disclosure) → `SensitiveInformation/` ✅
- P06 (Output Handling) → `OutputHandling/` (new)
- P07 (Availability) → `UnboundedConsumption/` (new)
- P05 (Agent/Tool Abuse) → `ExcessiveAgency/` (new)
- P03 (RAG Poisoning) → overlaps `VectorEmbedding/` (new)
- P08 (Model/API Access — auth/authz/tenant isolation) → infra-security, not one of the
  OWASP LLM01–10 risk entries at all. Possible future skill, not part of this OWASP-grounded
  batch.

---

## 4. New deliverable: the honest cross-test-case verdict report

Given one target URL and whichever test cases have been run against it, produce ONE document
(exact shape — `ui/shared/report_builder.py` vs. a new `/api/report` endpoint — decided at
build time) with:

1. **Per-risk rows**: OWASP's own live-fetched text (`meaning`) alongside a plain-English
   gloss written by us (`layman_meaning`) — same category of authored-not-fetched content as
   `RISK_TO_CONTROLS`, clearly labeled as our paraphrase, never presented as an OWASP quote.
2. **A verdict per risk**, never a bare pass/fail — always paired with the confidence label
   already produced by `classify()`/`_flag_duplicate_responses()` and what that label means
   in plain language (e.g. *"HELD means this specific attempt was refused — it does not mean
   this attack class is closed off, only that this one heuristic-matched refusal was
   observed."*).
3. **An overall summary** stating tested scope, untested scope (which OWASP risks this run
   did NOT cover, and why — pulled straight from each skill's own `applicability_note`/
   `NOT_APPLICABLE` reasoning), test date, target URL, and a standing limitations statement
   echoing OWASP control #11 and blueprint Rule #10. This is the "game changer" honesty
   requirement — not an afterthought paragraph at the bottom.
4. Same no-hardcoding rule applies: the report pulls `meaning`/`remediation` fresh from each
   test case's own `_get_reference()` at report-generation time — never a cached/bundled copy.

---

## 5. Build order for next session

1. `OutputHandling/` (LLM10) — new classifier logic, otherwise reuses the existing harness as-is.
2. `UnboundedConsumption/` (LLM06) — single-message risks first, burst-mode addition second.
3. `HiddenContext/` (LLM08) — straightforward, same shape as the first two test cases.
4. `ExcessiveAgency/` (LLM03) and `VectorEmbedding/` (LLM09) — both conditional on site
   capability signals already detected by `site_analyzer.py`.
5. `Misinformation/` (LLM07) — adversarial-prompt half only, eval-set gap documented.
6. Register all five in `ui/server.py`'s `TEST_CASES` dict.
7. Build the honest verdict report layer once at least two of the new test cases exist, so
   it's designed against real multi-test-case evidence, not a single case.

## 6. Verification

Same recipe already proven twice for the first two test cases: `python ui/server.py`,
`POST /api/analyze` against a real LLM site, confirm one distinct prompt set per registered
skill (no cross-contamination — same `_get_test_case_modules` module-loading pattern already
verified), `POST /api/test` per test case against the real endpoint, evidence JSON written to
each test case's own `evidence/adversarial/` folder.

For the report layer specifically: generate a report against a target where at least one risk
is `NOT_APPLICABLE` and at least one is `NEEDS_REVIEW`, confirm the rendered report states
both honestly (an untested-scope line for the `NOT_APPLICABLE` risk, an explicit "needs
manual verification" line for `NEEDS_REVIEW`) rather than omitting them or rounding up to a
clean pass.
