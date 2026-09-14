# The Finding shape

This documents the shape every IEM-AIS test case's evidence JSON already
produces, per prompt/risk, inside `run_full()`'s `results` list
(`ui/shared/inject_base.py`). It's written down here, formalized, rather
than left implicit, because `ui/shared/report_builder.py` (Phase 1 of
`Project DOCS/IEM-AIS-Platform-Evolution-Plan.md`) reads exactly this
shape across every test case to build one combined report. Nothing here
changes what any skill already writes -- this is documentation of an
existing contract, not a new one.

A plain Python `dict`, not a class/dataclass -- consistent with the rest
of this stdlib-only project. No validation library; a missing/`None`
field is handled defensively by every reader (see `report_builder.py`).

| Field | Source | Meaning |
|---|---|---|
| `risk_id` | `prompt_generator.build_prompts()` | The numbered OWASP "Common Example of Risk" this row tests. |
| `risk_name` | `prompt_generator.build_prompts()` | That risk's name, verbatim from the OWASP PDF. |
| `citation` | `prompt_generator.build_prompts()` | Exact page/section citation into the live-fetched OWASP PDF. |
| `applicable` | `prompt_generator.build_prompts()` | Whether this risk has a real channel to test at all (`False` -> never sent, see `applicability_note`). |
| `applicability_note` | `prompt_generator.build_prompts()` | Human-readable honesty statement about what this specific prompt can and can't prove -- every skill's "Applicability ceiling" reasoning lives here, per-risk. |
| `prompt` | `prompt_generator.build_prompts()` | The actual adversarial prompt text sent (or `None` if `applicable` is `False`). |
| `meaning` | `prompt_generator._get_reference()`, live OWASP fetch | OWASP's own text for this risk, fetched fresh every run, never a bundled/cached copy. |
| `remediation` | `prompt_generator._get_reference()`, live OWASP fetch + this project's own `RISK_TO_CONTROLS` judgment | Which live-fetched Prevention/Mitigation control(s) this project's own analysis maps to this risk. |
| `sent` | `inject_base.run_prompt_entry()` | Whether a real request was actually made for this risk (`False` for `NOT_APPLICABLE` rows). |
| `session_id` | `inject_base.run_prompt_entry()` | The per-request session identifier used (a fresh UUID per prompt, unless a followup shares one deliberately). |
| `response_text` | `inject_base.extract_reply()` | The real reply text extracted from the target's real response. |
| `raw_response` | `inject_base.call_endpoint()` | The full, unprocessed response body, kept for a human to inspect beyond what `extract_reply()` guessed. |
| `error` | `inject_base.call_endpoint()` | Non-`None` if the request itself failed (HTTP/connection/JSON error) -- distinct from a successful request whose *content* looks risky. |
| `elapsed_ms` | `inject_base.call_endpoint()` | Real wall-clock latency of the request, used by `UnboundedConsumption`'s latency-based classifier and available to every other skill. |
| `verdict` | each skill's own `classify()` | The heuristic verdict string. Always a sentence, never a bare label -- see "Verdict families" below. |
| `burst_stats` / `burst_calls` | `inject_base.run_burst()` (Denial-of-Wallet-style risks only) | Aggregate stats (`count`, `errors`, `avg_elapsed_ms`) plus each individual call, for the one risk shape that needs several rapid requests instead of one. |
| `followup_*` fields | `inject_base.run_prompt_entry()` (cross-session risks only) | A second prompt/response/verdict for risks that need a plant-then-trigger pattern across two messages. |

Batch-level fields (one level up, on the evidence dict `run_full()`
returns, not per-row):

| Field | Meaning |
|---|---|
| `probe_name` | This skill's identifier (e.g. `jailbreaking_generic`). |
| `target_url` | The exact URL this run was against. |
| `timestamp` | UTC ISO timestamp of the run. |
| `standard_citation` | The OWASP entry (page range) this whole skill is grounded in. |
| `site_profile` | The full `site_analyzer.analyze()` output for this target, kept for provenance. |
| `endpoint_used` | Which discovered endpoint this run actually sent to. |
| `verdict` | The **batch**-level verdict (`COMPLETE`, `NO LLM DETECTED...`, `ERROR`, etc.) -- distinct from each row's own per-risk `verdict`. |
| `results` | The list of per-risk Finding rows described above. |

## Verdict families

Every skill's `classify()` returns a full sentence, not an enum, so a
human reading one evidence file in isolation always sees the caveat
inline. For cross-test-case aggregation (`report_builder.py`,
Phase 2/3+'s SQLite index), a **verdict family** is derived by matching
a known prefix -- this parsing lives in `report_builder.py`, not in any
skill, since it's a presentation/aggregation concern, not a testing one:

- `HELD` -- the attempt was refused/deflected (a good outcome, for the
  skills where refusal is the point).
- `NEEDS_REVIEW` -- no refusal marker matched; a human must read
  `response_text` to judge what actually happened.
- `CLEAN` / `OUTPUT_UNSAFE` -- `OutputHandling`'s inverted pair (a raw
  dangerous pattern was, or wasn't, found in the reply).
- `BOUNDED` / `RESOURCE_RISK_OBSERVED` / `PARTIAL_THROTTLING_OBSERVED` --
  `UnboundedConsumption`'s length/latency/burst-based family.
- `NOT_APPLICABLE` -- never sent; the row's `applicability_note` states
  why, and this is never treated as a favorable result.
- `ERROR` -- the request itself failed; says nothing about the target's
  security posture either way.
- `DUPLICATE_RESPONSE` -- `flag_duplicate_responses()` detected a
  byte-identical reply across 2+ prompts in the same run, almost
  certainly canned/rate-limited rather than genuine engagement; the
  underlying heuristic verdict is preserved inside the string for
  reference, but the family itself is `DUPLICATE_RESPONSE`.
- `NO_RESPONSE` -- the target returned an empty reply.

**No family here is ever a bare pass.** `report_builder.py` is
responsible for pairing every family with what it does and doesn't
prove when it renders a report -- the same honesty requirement stated in
`CLAUDE.md` for every individual verdict applies to every aggregate
built on top of them.
