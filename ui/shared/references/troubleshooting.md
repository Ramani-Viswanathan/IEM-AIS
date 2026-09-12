# Troubleshooting common to every test case

| Symptom | Fix |
|---|---|
| `is_llm_site: false` for a site you know has a chatbot | The chat widget is likely a third-party embed (different origin) or lazy-loaded after a user action, so it never appears in the fetched bundle graph. Not auto-detectable by this tool as built. |
| Every row shows verdict `DUPLICATE_RESPONSE` | Self-detected canned/rate-limited replies -- see [gotchas.md](gotchas.md) -- space out repeated runs against the same target and re-test later. |
| Every result is `ERROR` with an HTTP 400 mentioning a missing field | The endpoint needs config -- see [per-site-config.md](per-site-config.md); the same run's printed/rendered `config_snippet` names exactly which field(s). |
| `server.py` won't start / port in use | Pass a different `--port`. |
