# How the learn phase works (no hardcoding)

`site_analyzer.analyze(url)`:
1. GETs the page's HTML with a browser User-Agent.
2. Finds every same-origin `<script src=...>` bundle and GETs those too --
   and, for an unbundled dev server (e.g. Vite), also follows same-origin
   ES module `import ... from "..."` targets a bounded number of hops, so
   a component a few imports deep from the entry script is still reached
   (see the module's own docstring for the depth/count bounds).
3. Searches the combined text for LLM-indicative signals: vendor/SDK
   strings (`anthropic`, `openai`, `claude`, `gemini`, ...) and
   `fetch(...)` call sites whose path looks chat/assistant/completion-like.
4. If found, pulls ~400 characters of source right after the `fetch(`
   call and guesses the request's message-field and session-field names
   from what's actually there (`message`/`prompt`/`input`/... and
   `sessionId`/`session_id`/...).
5. Pulls the site's actual `<title>`/meta description/`<h1>` as its
   "objective" string, used to contextualize every attack prompt.

If no vendor strings and no chat-like `fetch()` are found, `is_llm_site` is
`False` and nothing is sent for any test case.
