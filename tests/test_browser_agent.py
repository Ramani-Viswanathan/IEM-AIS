import shutil
import subprocess

import browser_agent


# ============================================================================
# _llm_call_via_cli / _llm_call_via_api / _default_llm_call -- the real LLM
# call paths. Exercised against monkeypatched subprocess/shutil/anthropic,
# never a real CLI invocation or network call in this suite.
# ============================================================================

def test_llm_call_via_cli_returns_stripped_stdout_on_success(monkeypatch):
    # Resolving the real executable path first (not a bare "claude") is
    # what makes this work on Windows, where an npm-installed CLI is a
    # .cmd shim CreateProcess can't resolve the way a shell's PATHEXT
    # lookup would -- confirmed live (2026-09-14): a bare "claude" raised
    # FileNotFoundError despite `which claude` finding it.
    monkeypatch.setattr(shutil, "which", lambda name: "/fake/path/claude")

    def fake_run(cmd, input, capture_output, text, timeout):
        assert cmd == ["/fake/path/claude", "-p"]
        assert input == "prompt"  # piped via stdin, never as a CLI argument (see docstring)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout='  {"input_idx": 0}  \n', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert browser_agent._llm_call_via_cli("prompt") == '{"input_idx": 0}'


def test_llm_call_via_cli_raises_clear_error_when_claude_not_on_path(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    try:
        browser_agent._llm_call_via_cli("prompt")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "not found on path" in str(e).lower()


def test_llm_call_via_cli_raises_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/fake/path/claude")

    def fake_run(cmd, input, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        browser_agent._llm_call_via_cli("prompt")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "boom" in str(e)


def test_llm_call_via_api_raises_clear_error_when_no_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    try:
        browser_agent._llm_call_via_api("prompt")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "claude" in str(e).lower() and "anthropic_api_key" in str(e).lower()


def test_default_llm_call_prefers_cli_when_available(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(browser_agent, "_llm_call_via_cli", lambda p: "cli-was-used")
    monkeypatch.setattr(browser_agent, "_llm_call_via_api", lambda p: "api-was-used")
    assert browser_agent._default_llm_call("prompt") == "cli-was-used"


def test_default_llm_call_falls_back_to_api_when_no_cli(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(browser_agent, "_llm_call_via_cli", lambda p: "cli-was-used")
    monkeypatch.setattr(browser_agent, "_llm_call_via_api", lambda p: "api-was-used")
    assert browser_agent._default_llm_call("prompt") == "api-was-used"


# ============================================================================
# render_snapshot_text / build_decision_prompt -- pure formatting, no I/O.
# ============================================================================

def test_render_snapshot_text_empty_is_honest():
    assert "no interactive elements" in browser_agent.render_snapshot_text([]).lower()


def test_render_snapshot_text_includes_descriptors():
    elements = [{"idx": 0, "tag": "textarea", "role": "", "type": "", "placeholder": "Type a message...", "ariaLabel": "", "text": ""}]
    text = browser_agent.render_snapshot_text(elements)
    assert "[0]" in text and "<textarea>" in text and "Type a message..." in text


def test_build_decision_prompt_embeds_elements_text():
    prompt = browser_agent.build_decision_prompt("[0] <textarea>")
    assert "[0] <textarea>" in prompt
    assert "JSON object" in prompt


# ============================================================================
# parse_decision -- the honesty-critical validation layer. Every case here
# is either a real, in-range action or an explicit {"error": ...} -- never
# a guess past what the LLM actually said.
# ============================================================================

def test_parse_decision_valid_full_action():
    raw = '{"input_idx": 2, "submit_idx": 5, "submit_via_enter": false}'
    result = browser_agent.parse_decision(raw, num_elements=10)
    assert result == {"input_idx": 2, "submit_idx": 5, "submit_via_enter": False}


def test_parse_decision_valid_enter_only_action():
    raw = '{"input_idx": 0, "submit_idx": null, "submit_via_enter": true}'
    result = browser_agent.parse_decision(raw, num_elements=3)
    assert result == {"input_idx": 0, "submit_idx": None, "submit_via_enter": True}


def test_parse_decision_defaults_submit_via_enter_true_when_absent():
    raw = '{"input_idx": 0}'
    result = browser_agent.parse_decision(raw, num_elements=3)
    assert result["submit_via_enter"] is True
    assert result["submit_idx"] is None


def test_parse_decision_honest_error_shape_passthrough():
    raw = '{"error": "no textbox-like element found"}'
    result = browser_agent.parse_decision(raw, num_elements=5)
    assert result == {"error": "no textbox-like element found"}


def test_parse_decision_no_text_at_all():
    assert "no text" in browser_agent.parse_decision(None, num_elements=5)["error"].lower()
    assert "no text" in browser_agent.parse_decision("", num_elements=5)["error"].lower()


def test_parse_decision_garbage_text_not_coerced():
    result = browser_agent.parse_decision("I think it's the third one, probably the textarea.", num_elements=5)
    assert "error" in result


def test_parse_decision_invalid_json_not_coerced():
    result = browser_agent.parse_decision("{not: valid json at all}", num_elements=5)
    assert "error" in result


def test_parse_decision_rejects_hallucinated_out_of_range_input_idx():
    # A real failure mode this must catch: the LLM points at an element
    # index that doesn't exist among the elements it was actually shown.
    raw = '{"input_idx": 99, "submit_idx": null, "submit_via_enter": true}'
    result = browser_agent.parse_decision(raw, num_elements=5)
    assert "error" in result
    assert "out of range" in result["error"].lower()


def test_parse_decision_rejects_out_of_range_submit_idx():
    raw = '{"input_idx": 0, "submit_idx": 99, "submit_via_enter": false}'
    result = browser_agent.parse_decision(raw, num_elements=5)
    assert "error" in result


def test_parse_decision_extracts_json_even_with_surrounding_prose():
    # Real LLMs sometimes wrap JSON in a sentence despite instructions --
    # this must still extract it rather than failing pedantically.
    raw = 'Sure, here it is: {"input_idx": 1, "submit_idx": null, "submit_via_enter": true} -- hope that helps!'
    result = browser_agent.parse_decision(raw, num_elements=3)
    assert result["input_idx"] == 1


# ============================================================================
# identify_chat_action -- wires elements -> prompt -> injected llm_call ->
# parse_decision, with zero real network/LLM calls (llm_call is a stub).
# ============================================================================

def test_identify_chat_action_no_elements_is_honest_without_calling_llm():
    calls = []
    result = browser_agent.identify_chat_action([], llm_call=lambda p: calls.append(p) or "should never run")
    assert "error" in result
    assert calls == []  # never even asked the LLM -- nothing to ask about


def test_identify_chat_action_planted_input_among_distractors():
    elements = [
        {"idx": 0, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "Close dialog", "text": "X"},
        {"idx": 1, "tag": "textarea", "role": "", "type": "", "placeholder": "Ask me anything...", "ariaLabel": "", "text": ""},
        {"idx": 2, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Send"},
    ]
    # Stub stands in for the real LLM's judgment -- what we're actually
    # testing is that identify_chat_action correctly threads that answer
    # straight through parse_decision's validation against these 3 elements.
    stub = lambda p: '{"input_idx": 1, "submit_idx": 2, "submit_via_enter": true}'
    result = browser_agent.identify_chat_action(elements, llm_call=stub)
    assert result == {"input_idx": 1, "submit_idx": 2, "submit_via_enter": True}


def test_identify_chat_action_llm_says_no_usable_input():
    elements = [{"idx": 0, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "Cookie settings", "text": "Accept"}]
    stub = lambda p: '{"error": "only a cookie-consent button is present, no chat input"}'
    result = browser_agent.identify_chat_action(elements, llm_call=stub)
    assert "cookie" in result["error"].lower()


# ============================================================================
# send_prompt_via_browser -- exercised against a fake Playwright-shaped
# Page double, so this needs neither the real `playwright` package nor a
# real browser. Covers: happy path via submit button, happy path via
# Enter, identification failure, vanished element, no-reply timeout.
# ============================================================================

class FakeElement:
    def __init__(self, page, idx):
        self._page = page
        self.idx = idx
        self.clicked = False
        self.filled_with = None
        self.pressed = None

    def click(self, timeout=None):
        self.clicked = True

    def fill(self, text):
        self.filled_with = text

    def press(self, key):
        self.pressed = key
        if key == "Enter" and self._page.reply_on_enter is not None:
            self._page._body_text = self._page.reply_on_enter


class FakePage:
    """Minimal stand-in for a Playwright Page -- implements exactly the
    surface send_prompt_via_browser() touches."""
    def __init__(self, elements, initial_body="", reply_after_submit=None, reply_on_enter=None,
                 raise_on_press=False, reveal_click_idx=None, elements_after_reveal=None,
                 reveal_click_fails_idx=()):
        self._elements = elements
        self._body_text = initial_body
        self.reply_after_submit = reply_after_submit
        self.reply_on_enter = reply_on_enter
        self.raise_on_press = raise_on_press
        self.reveal_click_idx = reveal_click_idx
        self.elements_after_reveal = elements_after_reveal
        self.reveal_click_fails_idx = set(reveal_click_fails_idx)
        self.reveal_clicked = False
        self.reveal_click_attempts = []
        self.wait_calls = []

    def eval_on_selector_all(self, selector, script, max_elements):
        return self._elements

    def query_selector(self, css_selector):
        # css_selector looks like "[data-iemais-idx='2']"
        idx = int(css_selector.split("'")[1])
        if idx >= len(self._elements):
            return None
        el = FakeElement(self, idx)
        if idx == getattr(self, "_submit_idx_for_click", None) and self.reply_after_submit is not None:
            orig_click = el.click
            def click_and_reply(timeout=None):
                orig_click(timeout=timeout)
                self._body_text = self.reply_after_submit
            el.click = click_and_reply
        if idx in self.reveal_click_fails_idx:
            def failing_click(timeout=None):
                self.reveal_click_attempts.append(idx)
                raise TimeoutError(f"ElementHandle.click: Timeout {timeout}ms exceeded.")
            el.click = failing_click
        elif idx == self.reveal_click_idx:
            orig_click = el.click
            def click_and_reveal(timeout=None):
                self.reveal_click_attempts.append(idx)
                orig_click(timeout=timeout)
                self.reveal_clicked = True
                if self.elements_after_reveal is not None:
                    self._elements = self.elements_after_reveal
            el.click = click_and_reveal
        if self.raise_on_press:
            def bad_press(key):
                raise RuntimeError("element detached from DOM")
            el.press = bad_press
        return el

    def inner_text(self, selector):
        return self._body_text

    def wait_for_timeout(self, ms):
        self.wait_calls.append(ms)


def test_send_prompt_via_browser_happy_path_via_submit_button():
    elements = [
        {"idx": 0, "tag": "textarea", "role": "", "type": "", "placeholder": "Ask...", "ariaLabel": "", "text": ""},
        {"idx": 1, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Send"},
    ]
    page = FakePage(elements, initial_body="Welcome to the chat.")
    page._submit_idx_for_click = 1
    page.reply_after_submit = "Welcome to the chat.\nBot: Hello, how can I help?"
    stub = lambda p: '{"input_idx": 0, "submit_idx": 1, "submit_via_enter": false}'

    result = browser_agent.send_prompt_via_browser(page, "hi there", llm_call=stub, reply_wait_ms=1)

    assert result["error"] is None
    assert "Bot: Hello, how can I help?" in result["response_text"]
    assert result["elapsed_ms"] >= 0


def test_send_prompt_via_browser_happy_path_via_enter():
    elements = [{"idx": 0, "tag": "textarea", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": ""}]
    page = FakePage(elements, initial_body="", reply_on_enter="A real reply appeared.")
    stub = lambda p: '{"input_idx": 0, "submit_idx": null, "submit_via_enter": true}'

    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=stub, reply_wait_ms=1)

    assert result["error"] is None
    assert result["response_text"] == "A real reply appeared."


def test_send_prompt_via_browser_identification_failure_is_error_not_crash():
    page = FakePage([], initial_body="")
    stub = lambda p: "should never be called"
    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=stub, reply_wait_ms=1)
    assert result["response_text"] is None
    assert "could not identify" in result["error"].lower()


def test_send_prompt_via_browser_no_new_text_is_honest_not_a_false_reply():
    elements = [{"idx": 0, "tag": "textarea", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": ""}]
    page = FakePage(elements, initial_body="Static page text that never changes.")
    stub = lambda p: '{"input_idx": 0, "submit_idx": null, "submit_via_enter": true}'
    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=stub, reply_wait_ms=1)
    assert result["response_text"] is None
    assert result["error"] is not None
    assert "no new text" in result["error"].lower()


# ============================================================================
# auth_state_path -- Phase 2 step 4 (saved logins). Pure path
# construction, no filesystem/network involved.
# ============================================================================

def test_auth_state_path_stable_and_scoped_by_origin_not_full_url():
    p1 = browser_agent.auth_state_path("https://example.com/chat/room1")
    p2 = browser_agent.auth_state_path("https://example.com/chat/room2")
    p3 = browser_agent.auth_state_path("https://other.example/")
    assert p1 == p2  # same origin -> same saved session, regardless of path
    assert p1 != p3
    assert p1.suffix == ".json"
    assert p1.parent == browser_agent.AUTH_STATE_DIR


def test_send_prompt_via_browser_llm_call_exception_becomes_error_not_crash():
    # Regression: a missing ANTHROPIC_API_KEY or a network/auth failure
    # calling the LLM must not crash the whole batch run -- it's an
    # honest ERROR entry for this one prompt, like a failed HTTP call.
    elements = [{"idx": 0, "tag": "textarea", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": ""}]
    page = FakePage(elements, initial_body="")

    def raising_llm_call(prompt_text):
        raise RuntimeError("ANTHROPIC_API_KEY is not set")

    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=raising_llm_call, reply_wait_ms=1)
    assert result["response_text"] is None
    assert "anthropic_api_key" in result["error"].lower()


def test_send_prompt_via_browser_playwright_exception_becomes_error_not_crash():
    elements = [{"idx": 0, "tag": "textarea", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": ""}]
    page = FakePage(elements, initial_body="", raise_on_press=True)
    stub = lambda p: '{"input_idx": 0, "submit_idx": null, "submit_via_enter": true}'
    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=stub, reply_wait_ms=1)
    assert result["response_text"] is None
    assert "browser interaction failed" in result["error"].lower()


# ============================================================================
# _find_reveal_candidates / the reveal-click retry in send_prompt_via_browser
# -- confirmed live (2026-09-14) against Lakera's Agent Breaker, whose real
# chat textarea doesn't exist in the DOM until its "Chat" tab is clicked,
# and which has more than one similarly-labeled element where only one is
# actually clickable at a given moment.
# ============================================================================

def test_find_reveal_candidates_matches_chat_labeled_buttons_in_order():
    elements = [
        {"idx": 0, "tag": "button", "text": "Settings", "ariaLabel": ""},
        {"idx": 1, "tag": "button", "text": "Chat", "ariaLabel": ""},
        {"idx": 2, "tag": "button", "text": "Chat", "ariaLabel": ""},
    ]
    candidates = browser_agent._find_reveal_candidates(elements)
    assert [c["idx"] for c in candidates] == [1, 2]


def test_find_reveal_candidates_empty_when_nothing_matches():
    elements = [{"idx": 0, "tag": "button", "text": "Settings", "ariaLabel": ""}]
    assert browser_agent._find_reveal_candidates(elements) == []


def test_send_prompt_via_browser_reveal_click_finds_input_after_retry():
    initial_elements = [{"idx": 0, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Chat"}]
    revealed_elements = [
        {"idx": 0, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Chat"},
        {"idx": 1, "tag": "textarea", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": ""},
    ]
    page = FakePage(initial_elements, initial_body="", reply_on_enter="Real reply appeared.",
                     reveal_click_idx=0, elements_after_reveal=revealed_elements)

    calls = []

    def stub(prompt_text):
        calls.append(prompt_text)
        if len(calls) == 1:
            return '{"error": "no textbox-like element found -- all listed elements are buttons"}'
        return '{"input_idx": 1, "submit_idx": null, "submit_via_enter": true}'

    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=stub, reply_wait_ms=1)
    assert result["error"] is None
    assert result["response_text"] == "Real reply appeared."
    assert page.reveal_clicked is True
    assert len(calls) == 2  # asked once, revealed more UI, asked again


def test_send_prompt_via_browser_no_reveal_candidate_gives_up_honestly():
    # No button here even LOOKS chat-related -- must not click blindly,
    # and must not retry the LLM call a second time for nothing.
    elements = [{"idx": 0, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Settings"}]
    page = FakePage(elements, initial_body="")
    calls = []

    def stub(p):
        calls.append(p)
        return '{"error": "no textbox-like element found"}'

    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=stub, reply_wait_ms=1)
    assert result["response_text"] is None
    assert "no textbox" in result["error"].lower()
    assert len(calls) == 1


def test_send_prompt_via_browser_reveal_click_still_fails_gives_up_honestly():
    # The reveal click happens, but even the post-reveal page still has no
    # usable input -- must still return an honest error, never fabricate.
    initial_elements = [{"idx": 0, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Chat"}]
    revealed_elements = [{"idx": 0, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Chat"}]
    page = FakePage(initial_elements, initial_body="", reveal_click_idx=0, elements_after_reveal=revealed_elements)
    stub = lambda p: '{"error": "no textbox-like element found"}'

    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=stub, reply_wait_ms=1)
    assert result["response_text"] is None
    assert "no textbox" in result["error"].lower()
    assert page.reveal_clicked is True


def test_send_prompt_via_browser_tries_next_reveal_candidate_when_first_times_out():
    # Regression: reproduces exactly what happened live against Lakera --
    # two elements both look chat-related, but the first one times out
    # waiting to become actionable. Must move on to the second rather than
    # giving up on the very first click failure.
    initial_elements = [
        {"idx": 0, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Chat"},
        {"idx": 1, "tag": "button", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": "Chat"},
    ]
    revealed_elements = initial_elements + [
        {"idx": 2, "tag": "textarea", "role": "", "type": "", "placeholder": "", "ariaLabel": "", "text": ""},
    ]
    page = FakePage(initial_elements, initial_body="", reply_on_enter="Real reply appeared.",
                     reveal_click_fails_idx={0}, reveal_click_idx=1, elements_after_reveal=revealed_elements)

    calls = []

    def stub(prompt_text):
        calls.append(prompt_text)
        if len(calls) == 1:
            return '{"error": "no textbox-like element found"}'
        return '{"input_idx": 2, "submit_idx": null, "submit_via_enter": true}'

    result = browser_agent.send_prompt_via_browser(page, "hi", llm_call=stub, reply_wait_ms=1)
    assert result["error"] is None
    assert result["response_text"] == "Real reply appeared."
    assert page.reveal_click_attempts == [0, 1]  # tried idx 0 first, it failed, moved on to idx 1
    assert page.reveal_clicked is True
