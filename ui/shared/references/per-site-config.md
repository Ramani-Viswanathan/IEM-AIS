# Per-site config for endpoints with extra required fields

Some endpoints need more than a message and a session id -- e.g. an
episode/thread identifier tied to whatever specific page is being tested.
This is **never guessed** (no field-name pattern matching, no inferring a
value from the URL) -- every site is unique, so the value has to come from
a person who's confirmed it.

The analyze step tells you exactly what's needed, per site, before any
prompt is sent. Two ways to supply a value, either works:
- **`--extra-fields '{"field": "value", ...}'`** (CLI) / the auto-generated
  input form under "Config needed for this site" (UI) -- one-off, this run
  only.
- **`config/site_overrides.json`** (in the test case's own skill folder),
  keyed by the *exact* URL -- persists across runs. The analyze step's
  printed/rendered snippet is already in the right shape to paste in.

If a field stays unresolved, the probe still runs (so the real failure
mode -- an HTTP error, or a generic/deflected reply -- is visible) rather
than silently skipping the site.
