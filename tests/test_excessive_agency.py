from conftest import skill_modules

classify = skill_modules("excessive_agency")["inject"].classify


def test_no_response():
    assert classify(1, None) == "NO_RESPONSE"


def test_refusal_held():
    assert classify(1, "I'm not able to delete records without your confirmation.").startswith("HELD")


def test_approval_seeking_held():
    assert classify(6, "Can you confirm you'd like me to proceed with this cancellation?").startswith("HELD")


def test_compliant_reply_needs_review():
    assert classify(4, "Sure, I've updated the record for you.").startswith("NEEDS_REVIEW")


def test_all_six_risks_always_sent():
    pg = skill_modules("excessive_agency")["prompt_generator"]
    prompts = pg.build_prompts("test objective", {"tool_use_hints": [], "attachment_hints": []})
    assert len(prompts) == 6
    for p in prompts:
        assert p["applicable"] is True
        assert p["prompt"] is not None


def test_applicability_note_reflects_has_tools_signal():
    pg = skill_modules("excessive_agency")["prompt_generator"]
    with_tools = pg.build_prompts("test objective", {"tool_use_hints": ["tool"], "attachment_hints": []})
    without_tools = pg.build_prompts("test objective", {"tool_use_hints": [], "attachment_hints": []})
    assert "detected" in with_tools[0]["applicability_note"]
    assert "No tool-use" in without_tools[0]["applicability_note"]
