import json
import sys

from conftest import inject_base


def test_extract_reply_dict_field():
    assert inject_base.extract_reply({"reply": "hi"}) == "hi"


def test_extract_reply_openai_choices_shape():
    res = {"choices": [{"message": {"content": "hi there"}}]}
    assert inject_base.extract_reply(res) == "hi there"


def test_extract_reply_string_passthrough():
    assert inject_base.extract_reply("plain string") == "plain string"


def test_extract_reply_fallback_never_raises():
    # no known field -- must return *something* stringified, not raise
    assert "weird" in inject_base.extract_reply({"weird": 1})


def test_pick_endpoint_none_when_empty():
    assert inject_base.pick_endpoint("http://x/", []) is None


def test_pick_endpoint_single():
    eps = [{"path": "/api/chat"}]
    assert inject_base.pick_endpoint("http://x/", eps) == eps[0]


def test_pick_endpoint_prefers_url_token_match():
    eps = [{"path": "/api/chat"}, {"path": "/api/liftoff-chat"}]
    assert inject_base.pick_endpoint("http://x/liftoff", eps)["path"] == "/api/liftoff-chat"


def test_load_overrides_missing_file_returns_empty(tmp_path):
    assert inject_base.load_overrides("http://x/", tmp_path) == {}


def test_load_overrides_returns_matching_url_entry(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "site_overrides.json").write_text(
        '{"http://x/": {"episodeSlug": "ep-1"}}', encoding="utf-8"
    )
    assert inject_base.load_overrides("http://x/", tmp_path) == {"episodeSlug": "ep-1"}
    assert inject_base.load_overrides("http://other/", tmp_path) == {}


def test_flag_duplicate_responses_relabels_matching_pairs():
    results = [
        {"sent": True, "response_text": "same canned reply", "verdict": "HELD"},
        {"sent": True, "response_text": "same canned reply", "verdict": "NEEDS_REVIEW"},
        {"sent": True, "response_text": "a distinct reply", "verdict": "HELD"},
    ]
    inject_base.flag_duplicate_responses(results)
    assert results[0]["verdict"].startswith("DUPLICATE_RESPONSE")
    assert results[1]["verdict"].startswith("DUPLICATE_RESPONSE")
    assert results[2]["verdict"] == "HELD"  # untouched -- no duplicate


def _classify_stub(risk_id, response_text, elapsed_ms=None, burst_stats=None):
    if burst_stats is not None:
        return f"BURST({burst_stats['errors']}/{burst_stats['count']})"
    return "STUB_VERDICT"


def test_run_prompt_entry_not_applicable_when_prompt_is_none():
    entry = inject_base.run_prompt_entry(
        "http://x", {"path": "/api/chat", "message_field_guess": "message"}, {},
        {"risk_id": 1, "prompt": None}, _classify_stub,
    )
    assert entry["sent"] is False
    assert entry["verdict"] == "NOT_APPLICABLE"


def test_run_prompt_entry_error_when_call_fails(monkeypatch):
    monkeypatch.setattr(
        inject_base, "call_endpoint",
        lambda *a, **k: {"request_body": {}, "response_text": None, "raw_response": None,
                          "error": "Connection failed: fake", "elapsed_ms": 5},
    )
    entry = inject_base.run_prompt_entry(
        "http://x", {"path": "/api/chat", "message_field_guess": "message"}, {},
        {"risk_id": 1, "prompt": "hello"}, _classify_stub,
    )
    assert entry["sent"] is True
    assert entry["verdict"] == "ERROR"


def test_run_prompt_entry_classifies_on_success(monkeypatch):
    monkeypatch.setattr(
        inject_base, "call_endpoint",
        lambda *a, **k: {"request_body": {}, "response_text": "a reply", "raw_response": {},
                          "error": None, "elapsed_ms": 5},
    )
    entry = inject_base.run_prompt_entry(
        "http://x", {"path": "/api/chat", "message_field_guess": "message"}, {},
        {"risk_id": 1, "prompt": "hello"}, _classify_stub,
    )
    assert entry["verdict"] == "STUB_VERDICT"


def test_extra_fields_from_overrides_strips_endpoint_override_key():
    overrides = {"_endpoint_override": {"path": "/api/v2/chat"}, "episodeSlug": "ep-1"}
    assert inject_base.extra_fields_from_overrides(overrides) == {"episodeSlug": "ep-1"}


def test_resolve_endpoint_prefers_override_even_when_no_endpoints_detected(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "site_overrides.json").write_text(json.dumps({
        "http://x/": {"_endpoint_override": {
            "path": "/api/real-chat", "message_field_guess": "input",
            "session_field_guess": "conversation_id", "headers": {"Authorization": "Bearer tok"},
        }},
    }), encoding="utf-8")
    profile = {"endpoints": []}  # exactly the Lakera-style gap: site detected, no endpoint found
    endpoint = inject_base.resolve_endpoint("http://x/", profile, tmp_path)
    assert endpoint["path"] == "/api/real-chat"
    assert endpoint["message_field_guess"] == "input"
    assert endpoint["session_field_guess"] == "conversation_id"
    assert endpoint["headers"] == {"Authorization": "Bearer tok"}


def test_resolve_endpoint_falls_back_to_pick_endpoint_when_no_override(tmp_path):
    profile = {"endpoints": [{"path": "/api/chat", "message_field_guess": "message"}]}
    endpoint = inject_base.resolve_endpoint("http://x/", profile, tmp_path)
    assert endpoint["path"] == "/api/chat"
    assert endpoint["headers"] == {}


def test_resolve_endpoint_none_when_neither_override_nor_endpoints(tmp_path):
    assert inject_base.resolve_endpoint("http://x/", {"endpoints": []}, tmp_path) is None


def test_call_endpoint_merges_override_headers(monkeypatch):
    captured = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({"reply": "hi"}).encode()

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.header_items())
        captured["full_url"] = req.full_url
        return FakeResp()

    monkeypatch.setattr(inject_base.urllib.request, "urlopen", fake_urlopen)
    endpoint = {"path": "/api/chat", "message_field_guess": "message", "headers": {"Authorization": "Bearer tok"}}
    result = inject_base.call_endpoint("http://origin", endpoint, "hello", "sess-1")
    assert captured["headers"].get("Authorization") == "Bearer tok"
    assert captured["full_url"] == "http://origin/api/chat"
    assert result["error"] is None


def test_call_endpoint_honors_absolute_url_in_endpoint_path(monkeypatch):
    captured = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({"reply": "hi"}).encode()

    def fake_urlopen(req, timeout=None):
        captured["full_url"] = req.full_url
        return FakeResp()

    monkeypatch.setattr(inject_base.urllib.request, "urlopen", fake_urlopen)
    endpoint = {"path": "https://api.other-host.example/chat", "message_field_guess": "message"}
    inject_base.call_endpoint("http://origin", endpoint, "hello", "sess-1")
    assert captured["full_url"] == "https://api.other-host.example/chat"


def test_open_browser_fallback_returns_none_without_playwright_installed(monkeypatch):
    # Forces the "playwright not installed" ImportError path regardless of
    # whether the real package happens to be installed in THIS environment
    # (it may be, once Phase 2's live verification has been run) -- keeps
    # this suite's zero-real-network convention either way, and confirms
    # the graceful no-op (Phase 2's fallback is a no-op, not a crash, until
    # a human opts in by installing the optional dependency).
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    assert inject_base.open_browser_fallback("http://x/") is None


def test_open_browser_fallback_loads_saved_auth_state_when_present(monkeypatch, tmp_path):
    """Regression: a saved login (Phase 2 step 4) must actually get
    passed into Playwright's new_context(storage_state=...), not just
    exist on disk unused -- verified against a fake playwright.sync_api
    module (not the real package, which isn't installed in this suite)."""
    import browser_agent
    saved_state = tmp_path / "state.json"
    saved_state.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(browser_agent, "auth_state_path", lambda url: saved_state)

    calls = {}

    class FakePage:
        def goto(self, url, timeout=None, wait_until=None):
            calls["goto_url"] = url

    class FakeContext:
        def new_page(self):
            return FakePage()

    class FakeBrowser:
        def new_context(self, storage_state=None):
            calls["storage_state"] = storage_state
            return FakeContext()

        def close(self):
            calls["closed"] = True

    class FakeChromium:
        def launch(self, headless=None):
            return FakeBrowser()

    class FakePW:
        chromium = FakeChromium()

        def stop(self):
            calls["stopped"] = True

    class FakeSyncPlaywrightCM:
        def start(self):
            return FakePW()

    fake_pkg = type(sys)("playwright")
    fake_submod = type(sys)("playwright.sync_api")
    fake_submod.sync_playwright = lambda: FakeSyncPlaywrightCM()
    fake_pkg.sync_api = fake_submod
    monkeypatch.setitem(sys.modules, "playwright", fake_pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_submod)

    ctx = inject_base.open_browser_fallback("https://example.com/chat")
    assert ctx is not None
    assert calls["storage_state"] == str(saved_state)
    ctx["close"]()
    assert calls["closed"] is True
    assert calls["stopped"] is True


def test_open_browser_fallback_uses_fresh_context_when_no_saved_state(monkeypatch, tmp_path):
    import browser_agent
    monkeypatch.setattr(browser_agent, "auth_state_path", lambda url: tmp_path / "never_saved.json")

    calls = {}

    class FakePage:
        def goto(self, url, timeout=None, wait_until=None):
            pass

    class FakeContext:
        def new_page(self):
            return FakePage()

    class FakeBrowser:
        def new_context(self, storage_state=None):
            calls["storage_state"] = storage_state
            return FakeContext()

    class FakeChromium:
        def launch(self, headless=None):
            return FakeBrowser()

    class FakePW:
        chromium = FakeChromium()

        def stop(self):
            pass

    class FakeSyncPlaywrightCM:
        def start(self):
            return FakePW()

    fake_pkg = type(sys)("playwright")
    fake_submod = type(sys)("playwright.sync_api")
    fake_submod.sync_playwright = lambda: FakeSyncPlaywrightCM()
    fake_pkg.sync_api = fake_submod
    monkeypatch.setitem(sys.modules, "playwright", fake_pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_submod)

    ctx = inject_base.open_browser_fallback("https://example.com/chat")
    assert ctx is not None
    assert calls["storage_state"] is None  # no saved login -- a plain, cookie-less context


def _fake_llm_profile():
    return {"is_llm_site": True, "endpoints": [], "origin": "http://x", "objective": "obj",
            "tool_use_hints": [], "attachment_hints": []}


def test_run_full_falls_through_to_honest_verdict_when_browser_fallback_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(inject_base.site_analyzer, "analyze", lambda url: _fake_llm_profile())
    monkeypatch.setattr(inject_base, "open_browser_fallback", lambda url: None)
    evidence = inject_base.run_full(
        "http://x/", build_prompts_fn=lambda *a, **k: [{"risk_id": 1, "prompt": "p"}],
        classify_fn=_classify_stub, probe_name="p", standard_citation="c", skill_dir=tmp_path,
    )
    assert "NO CALLABLE ENDPOINT" in evidence["verdict"]
    assert evidence["results"] == []


def test_run_full_uses_browser_fallback_when_no_http_endpoint_found(monkeypatch, tmp_path):
    import browser_agent
    monkeypatch.setattr(inject_base.site_analyzer, "analyze", lambda url: _fake_llm_profile())
    closed = []
    monkeypatch.setattr(inject_base, "open_browser_fallback",
                         lambda url: {"page": object(), "close": lambda: closed.append(True)})
    monkeypatch.setattr(browser_agent, "send_prompt_via_browser",
                         lambda page, msg, llm_call=None, reply_wait_ms=20000: {
                             "response_text": "a real reply", "raw_response": {}, "error": None, "elapsed_ms": 5,
                         })

    evidence = inject_base.run_full(
        "http://x/", build_prompts_fn=lambda *a, **k: [{"risk_id": 1, "prompt": "hi"}],
        classify_fn=_classify_stub, probe_name="p", standard_citation="c", skill_dir=tmp_path,
    )
    assert evidence["verdict"] == "COMPLETE"
    assert evidence["browser_fallback_used"] is True
    assert "verify manually" in evidence["browser_fallback_note"].lower()
    assert evidence["results"][0]["response_text"] == "a real reply"
    assert evidence["results"][0]["verdict"] == "STUB_VERDICT"
    assert closed == [True]  # browser closed exactly once


def test_run_full_closes_browser_even_when_a_prompt_errors(monkeypatch, tmp_path):
    import browser_agent
    monkeypatch.setattr(inject_base.site_analyzer, "analyze", lambda url: _fake_llm_profile())
    closed = []
    monkeypatch.setattr(inject_base, "open_browser_fallback",
                         lambda url: {"page": object(), "close": lambda: closed.append(True)})
    monkeypatch.setattr(browser_agent, "send_prompt_via_browser",
                         lambda page, msg, llm_call=None, reply_wait_ms=20000: {
                             "response_text": None, "raw_response": None,
                             "error": "Could not identify a usable chat input: ANTHROPIC_API_KEY is not set",
                             "elapsed_ms": 5,
                         })
    evidence = inject_base.run_full(
        "http://x/", build_prompts_fn=lambda *a, **k: [{"risk_id": 1, "prompt": "hi"}],
        classify_fn=_classify_stub, probe_name="p", standard_citation="c", skill_dir=tmp_path,
    )
    assert evidence["results"][0]["verdict"] == "ERROR"
    assert closed == [True]


def test_run_prompt_entry_burst_path(monkeypatch):
    calls = [
        {"session_id": "s1", "response_text": "r", "raw_response": {}, "error": None, "elapsed_ms": 10},
        {"session_id": "s2", "response_text": "r", "raw_response": {}, "error": "boom", "elapsed_ms": 10},
    ]
    monkeypatch.setattr(inject_base, "run_burst", lambda *a, **k: calls)
    entry = inject_base.run_prompt_entry(
        "http://x", {"path": "/api/chat", "message_field_guess": "message"}, {},
        {"risk_id": 2, "prompt": "hello", "burst": True, "burst_count": 2}, _classify_stub,
    )
    assert entry["verdict"] == "BURST(1/2)"
    assert entry["burst_stats"]["errors"] == 1
    assert entry["burst_stats"]["count"] == 2
