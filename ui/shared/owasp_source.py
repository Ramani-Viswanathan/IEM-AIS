#!/usr/bin/env python3
"""
Live OWASP source fetcher -- generic primitives, no bundled copy of any
standard's text, no risk-specific content. Shared by every test case's
own prompt_generator.py (each owns its own risk-to-control mapping and
extraction calls -- that's curated analysis, not fetchable data).

Discovers and fetches the current OWASP GenAI LLM Top 10 PDF directly from
genai.owasp.org at runtime, the same way site_analyzer.py discovers a
target site's API contract: fetch a page, find the real link in it, follow
that link -- never a hardcoded document ID or a checked-in static copy.

Verified this session: genai.owasp.org's LIVE per-risk pages
(.../llmrisk/llm01-prompt-injection/) still serve the 2025 edition (its
own <title> says so), but the resource landing page
https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ links to a
/download/<id>/ URL that serves the real 2026 PDF (confirmed via
Content-Disposition: filename="OWASP-GenAI-LLM-Top-10-2026-v1.0.pdf").
The numeric id is NOT hardcoded here -- it's discovered fresh from the
landing page's own HTML every time, since it's a WordPress
Download-Monitor id that could change if OWASP re-uploads the file.

Gotcha found building the 2nd test case (Sensitive Information /
LLM02:2026): the PDF's table of contents (page 3) repeats every entry's
"LLM0N:2026 <Name>" title, so a plain full_text.find() for a heading can
land on the ToC line instead of the real section. find_entry_section()
below only accepts a match if "Description" appears shortly after it,
which the ToC line never has -- confirmed necessary live: without it,
LLM02 extraction silently scoped to a ~50-character slice.
"""

import io
import re
import urllib.request
import urllib.error
from urllib.parse import urljoin

RESOURCE_PAGE = "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"
UA = "Mozilla/5.0 (compatible; IEM-AIS-OWASPSourceFetcher/1.0)"

DOWNLOAD_LINK_RE = re.compile(r'href=["\'](https?://genai\.owasp\.org/download/\d+/[^"\']*)["\']')

_cache = {}


def _fetch(url, max_bytes=10_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read(max_bytes)


def _discover_pdf_url():
    html = _fetch(RESOURCE_PAGE).decode("utf-8", errors="replace")
    m = DOWNLOAD_LINK_RE.search(html)
    if not m:
        raise RuntimeError(f"Could not find a /download/<id>/ link on {RESOURCE_PAGE} -- "
                            f"the page structure may have changed.")
    return urljoin(RESOURCE_PAGE, m.group(1))


def fetch_pdf_text():
    """Live PDF text, cached in-process after the first call (per server/
    CLI run -- never persisted to disk)."""
    if "full_text" in _cache:
        return _cache["full_text"]
    import pypdf  # only required if a live-reference feature is used
    pdf_url = _discover_pdf_url()
    pdf_bytes = _fetch(pdf_url)
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    full_text = "\n".join(page.extract_text() or "" for page in reader.pages)
    # Strip the PDF's own repeated page-header/footer boilerplate
    # ("Page 13 genai.owasp.org") that pypdf inlines mid-paragraph at page
    # breaks -- an artifact of the PDF's layout, not part of the standard's
    # actual text.
    full_text = re.sub(r"\s*Page\s+\d+\s*\n?\s*genai\.owasp\.org\s*", "\n", full_text)
    _cache["full_text"] = full_text
    _cache["pdf_url"] = pdf_url
    return full_text


def pdf_url():
    """The live PDF's URL for this process -- populated after fetch_pdf_text()."""
    return _cache.get("pdf_url")


def normalize(s):
    return re.sub(r"\s+", " ", s).strip()


def find_entry_section(full_text, heading, confirm_near="Description", search_from=0, window=200):
    """Finds the REAL occurrence of an entry heading like 'LLM02:2026
    Sensitive' -- skips the table-of-contents line, which repeats every
    heading but is never followed shortly by 'Description'. Returns the
    start index, or raises if no confirmed occurrence exists."""
    pos = search_from
    while True:
        idx = full_text.find(heading, pos)
        if idx == -1:
            raise RuntimeError(f"Could not find a confirmed occurrence of heading {heading!r} "
                                f"(checked for {confirm_near!r} within {window} chars after each match) "
                                f"in the fetched PDF text -- the document structure may have changed.")
        if confirm_near in full_text[idx: idx + window]:
            return idx
        pos = idx + len(heading)


def extract_numbered_section(section_text, start_heading, end_heading, expected_ids):
    """section_text should already be scoped to one entry (see
    find_entry_section) -- start_heading/end_heading are searched for
    within it only, so repeated headings elsewhere in the document can't
    be matched by mistake."""
    start = section_text.find(start_heading)
    end = section_text.find(end_heading, start) if start != -1 else -1
    if start == -1 or end == -1:
        raise RuntimeError(f"Could not find section between {start_heading!r} and {end_heading!r} "
                            f"in the given text -- the document structure may have changed.")
    body = section_text[start + len(start_heading):end]

    items = {}
    matches = list(re.finditer(r"(?:^|\n)\s*(\d{1,2})\.\s+", body))
    for i, m in enumerate(matches):
        num = int(m.group(1))
        if num not in expected_ids:
            continue
        item_start = m.end()
        item_end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        items[num] = normalize(body[item_start:item_end])

    missing = expected_ids - items.keys()
    if missing:
        raise RuntimeError(f"Expected items {sorted(expected_ids)} in section {start_heading!r}, "
                            f"but couldn't parse {sorted(missing)} from the given text.")
    return items
