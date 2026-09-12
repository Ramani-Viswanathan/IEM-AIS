# Gotchas common to every test case

- **Verdict is a heuristic, not ground truth.** Every skill's classifier
  (refusal-marker matching, dangerous-pattern matching, or length/latency
  thresholds -- see that skill's own `SKILL.md`) is a heuristic, not a
  human judgment. Always read `response_text` before drawing a conclusion.
- **A canned/rate-limited reply is self-detected, not something to spot
  manually.** `inject_base.flag_duplicate_responses()` runs after a batch
  (except UnboundedConsumption, which never ran this step -- its verdicts
  are latency/length-based, not refusal-based, so a canned reply doesn't
  mask them the same way): if 2+ prompts in that run got a byte-identical
  reply, every one of them is overridden to `DUPLICATE_RESPONSE (...)`
  instead of a misleadingly-neutral verdict. This compares THIS run's own
  outputs against each other -- no target-specific canned-message text is
  assumed, so it works for any site's rate-limit/canned-reply behavior.
- **`message_field_guess`/`session_field_guess` are pattern-matched
  against the endpoint's own literal source, not fabricated** -- for a
  site whose bundle doesn't spell field names near the `fetch(` call, the
  guess defaults to `message` / no session field. Verify with one look at
  `site_profile.endpoints[N].raw_context` in the evidence file if results
  look wrong. Anything beyond these two fields (`extra_fields`) is never
  guessed at all -- see [per-site-config.md](per-site-config.md).
- **Multiple endpoints can share one JS bundle.** A site-wide `/api/chat`
  plus a page-specific `/api/liftoff-chat` both show up in every page's
  bundle regardless of which page is being tested. `inject_base.
  pick_endpoint()` scores each candidate against the tested URL's own path
  tokens and picks the best match -- don't assume `endpoints[0]` is the
  one actually used; check `evidence["endpoint_used"]`.
- **Same-origin bundles only.** A site whose chat widget is a third-party
  embed (loaded from a different domain) won't be found by the analyzer --
  it only follows same-origin `<script>` tags and same-origin ES module
  imports. This is a real, current limitation.
