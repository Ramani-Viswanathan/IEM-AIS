# Live OWASP reference (no bundled copy)

The "what it means" / remediation text shown for each risk is fetched live
from OWASP's own site every time it's needed, never stored in this
codebase. Split across two places:
- `ui/shared/owasp_source.py` (shared, generic, reused by every test
  case): fetches `https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/`,
  finds its real `/download/<id>/` link (not hardcoded -- a WordPress
  Download-Monitor id that can change if OWASP re-uploads the file),
  fetches that PDF, extracts text with `pypdf`, and provides
  `find_entry_section()`/`extract_numbered_section()` generic primitives --
  no risk-specific content lives here.
- Each skill's own `prompt_generator.py` (`_get_reference()`): scopes the
  live text to that skill's own OWASP entry using `find_entry_section()`,
  then parses the numbered "Common Examples of Risk" and "Prevention and
  Mitigation Strategies" out of it.

## Table-of-contents guard

The PDF's table of contents repeats every `LLM0N:2026 <Name>` heading, so a
naive `full_text.find()` for a risk name can land on the ToC line instead
of the real section. `find_entry_section()` fixes this once, for every
skill, by only accepting a match followed shortly by a `confirm_near`
string (e.g. `"Description"`). If a new risk entry is added, reuse
`find_entry_section()` -- don't re-add a plain `.find()`.

## RISK_TO_CONTROLS is curated, not an OWASP fact

Which control numbers address which risk (`RISK_TO_CONTROLS`, in each
skill's own `prompt_generator.py`) is that skill's own analysis, not an
OWASP fact -- the PDF doesn't cross-reference risks to controls itself, so
only the meaning/control *text* is live; the mapping between them is
curated per skill.

## Fetch failure is disclosed, not papered over

If the fetch fails (no internet, OWASP site down, page structure changed),
every risk's `meaning`/`remediation` says so plainly instead of silently
falling back to stale text -- attack-sending still works either way, since
it doesn't depend on this.
