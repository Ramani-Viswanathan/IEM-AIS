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
