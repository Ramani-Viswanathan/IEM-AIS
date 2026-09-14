import json

import report_builder
from layman_glosses import get_layman_gloss
from conftest import skill_modules


def test_verdict_family_recognizes_known_prefixes():
    assert report_builder.verdict_family("HELD (refusal marker matched -- heuristic)") == "HELD"
    assert report_builder.verdict_family("NEEDS_REVIEW (no refusal marker matched)") == "NEEDS_REVIEW"
    assert report_builder.verdict_family("NOT_APPLICABLE") == "NOT_APPLICABLE"
    assert report_builder.verdict_family("DUPLICATE_RESPONSE (3 of this run's prompts...)") == "DUPLICATE_RESPONSE"
    assert report_builder.verdict_family("ERROR") == "ERROR"
    assert report_builder.verdict_family(None) == "UNKNOWN"
    assert report_builder.verdict_family("SOMETHING_NEW") == "UNKNOWN"


def test_family_meaning_never_empty_for_known_or_unknown_family():
    assert report_builder.family_meaning("HELD")
    assert report_builder.family_meaning("TOTALLY_UNRECOGNIZED")


def _canned_evidence(target_url, timestamp, results):
    return {
        "probe_name": "jailbreaking_generic",
        "target_url": target_url,
        "timestamp": timestamp,
        "standard_citation": "OWASP GenAI LLM Top 10 2026, LLM01:2026",
        "endpoint_used": "/api/chat",
        "verdict": "COMPLETE",
        "results": results,
    }


def _row(risk_id, risk_name, sent, verdict, applicability_note=None):
    return {
        "risk_id": risk_id,
        "risk_name": risk_name,
        "citation": f"OWASP LLM01:2026 p.12 risk #{risk_id}",
        "sent": sent,
        "meaning": "OWASP's own text for this risk.",
        "remediation": ["Control #1: do the thing."],
        "verdict": verdict,
        "applicability_note": applicability_note,
        "response_text": "some reply text" if sent else None,
    }


def test_build_report_separates_tested_and_untested_scope():
    evidence = _canned_evidence("https://example.com/", "2026-09-13T00:00:00Z", [
        _row(1, "Direct prompt-input override", True, "HELD (refusal marker matched)"),
        _row(7, "Fine-tuning interface as gradient oracle", False, "NOT_APPLICABLE",
             applicability_note="No fine-tuning API exists on a chat endpoint; not sent."),
    ])
    report = report_builder.build_report("https://example.com/", {"jailbreaking": evidence}, {"jailbreaking": "Test Case 1: Jailbreaking"})

    assert len(report["tested_scope"]) == 1
    assert report["tested_scope"][0]["risk_id"] == 1
    assert len(report["untested_scope"]) == 1
    assert report["untested_scope"][0]["risk_id"] == 7
    assert "fine-tuning" in report["untested_scope"][0]["reason"].lower()
    assert "not a guarantee" in report["limitations_statement"].lower()


def test_build_report_never_presents_not_applicable_as_favorable():
    evidence = _canned_evidence("https://example.com/", "2026-09-13T00:00:00Z", [
        _row(2, "Embedding Inversion", False, "NOT_APPLICABLE",
             applicability_note="Requires raw stored vectors; not sent."),
    ])
    report = report_builder.build_report("https://example.com/", {"vector_embedding": evidence})
    row = report["per_test_case"]["vector_embedding"]["rows"][0]
    assert row["verdict_family"] == "NOT_APPLICABLE"
    assert "not a favorable result" in row["verdict_family_meaning"].lower()


def test_build_report_carries_layman_gloss_and_flags_missing_ones():
    evidence = _canned_evidence("https://example.com/", "2026-09-13T00:00:00Z", [
        _row(1, "Direct prompt-input override", True, "HELD (refusal marker matched)"),
    ])
    report = report_builder.build_report("https://example.com/", {"jailbreaking": evidence})
    row = report["per_test_case"]["jailbreaking"]["rows"][0]
    assert row["layman_meaning"]
    assert "no plain-english gloss" not in row["layman_meaning"].lower()

    # A test case/risk_id combination with no authored gloss must say so honestly.
    from layman_glosses import get_layman_gloss
    assert "no plain-english gloss" in get_layman_gloss("not_a_real_test_case", 999).lower()


def test_render_markdown_states_needs_review_verify_manually():
    evidence = _canned_evidence("https://example.com/", "2026-09-13T00:00:00Z", [
        _row(1, "Direct prompt-input override", True,
             "NEEDS_REVIEW (no refusal marker matched -- verify manually, may be compliance or an unrelated reply)"),
    ])
    report = report_builder.build_report("https://example.com/", {"jailbreaking": evidence}, {"jailbreaking": "Test Case 1: Jailbreaking"})
    md = report_builder.render_markdown(report)
    assert "verify manually" in md.lower()
    assert "NEEDS_REVIEW" in md


def test_render_markdown_lists_untested_scope_section():
    evidence = _canned_evidence("https://example.com/", "2026-09-13T00:00:00Z", [
        _row(7, "Fine-tuning interface as gradient oracle", False, "NOT_APPLICABLE",
             applicability_note="No fine-tuning API exists on a chat endpoint; not sent."),
    ])
    report = report_builder.build_report("https://example.com/", {"jailbreaking": evidence}, {"jailbreaking": "Test Case 1: Jailbreaking"})
    md = report_builder.render_markdown(report)
    assert "Tested Scope vs Untested Scope" in md
    assert "Fine-tuning interface" in md


def test_render_markdown_never_produces_bare_pass_language():
    evidence = _canned_evidence("https://example.com/", "2026-09-13T00:00:00Z", [
        _row(1, "Direct prompt-input override", True, "HELD (refusal marker matched -- heuristic, verify manually)"),
    ])
    report = report_builder.build_report("https://example.com/", {"jailbreaking": evidence}, {"jailbreaking": "Test Case 1: Jailbreaking"})
    md = report_builder.render_markdown(report)
    forbidden = ["SECURE", "PASSED", "100% safe", "guaranteed safe"]
    low = md.lower()
    for word in forbidden:
        assert word.lower() not in low


def test_find_latest_evidence_picks_newest_matching_url(tmp_path):
    (tmp_path / "old.json").write_text(json.dumps(_canned_evidence("https://a.com/", "2026-09-01T00:00:00Z", [])), encoding="utf-8")
    (tmp_path / "new.json").write_text(json.dumps(_canned_evidence("https://a.com/", "2026-09-13T00:00:00Z", [])), encoding="utf-8")
    (tmp_path / "other_url.json").write_text(json.dumps(_canned_evidence("https://b.com/", "2026-09-14T00:00:00Z", [])), encoding="utf-8")
    (tmp_path / "single_shape.json").write_text(json.dumps({"target_url": "https://a.com/", "risk_id": 1, "verdict": "HELD"}), encoding="utf-8")
    (tmp_path / "not_json.json").write_text("{not valid json", encoding="utf-8")

    found = report_builder.find_latest_evidence(tmp_path, "https://a.com/")
    assert found is not None
    assert found["timestamp"] == "2026-09-13T00:00:00Z"


def test_find_latest_evidence_returns_none_for_missing_dir_or_no_match(tmp_path):
    assert report_builder.find_latest_evidence(tmp_path / "does_not_exist", "https://a.com/") is None
    (tmp_path / "run.json").write_text(json.dumps(_canned_evidence("https://a.com/", "2026-09-13T00:00:00Z", [])), encoding="utf-8")
    assert report_builder.find_latest_evidence(tmp_path, "https://no-match.com/") is None


def test_report_never_claims_full_coverage_when_no_risks_were_generated():
    """Regression: a batch with an empty results list (e.g. batch verdict
    was NO LLM DETECTED, so build_prompts() was never even called) must
    NOT be reported as 'every risk row was sent' -- that's a real
    coverage gap, not silence to omit."""
    evidence = _canned_evidence("https://example.com/", "2026-09-13T00:00:00Z", [])
    evidence["verdict"] = "NO LLM DETECTED -- this site does not have LLM"
    report = report_builder.build_report("https://example.com/", {"jailbreaking": evidence}, {"jailbreaking": "Test Case 1: Jailbreaking"})

    assert report["tested_scope"] == []
    assert len(report["untested_scope"]) == 1
    assert report["untested_scope"][0]["test_case"] == "jailbreaking"
    assert "no llm detected" in report["untested_scope"][0]["reason"].lower()

    md = report_builder.render_markdown(report)
    assert "every risk row" not in md.lower()


def test_render_markdown_reports_no_evidence_found_honestly():
    report = report_builder.build_report("https://never-tested.example/", {})
    md = report_builder.render_markdown(report)
    assert "no evidence found" in md.lower()
    assert "every risk row" not in md.lower()


def test_every_real_risk_across_every_skill_has_an_authored_layman_gloss():
    """Catches transcription mistakes (a wrong risk_id, a typo'd test-case
    key) between layman_glosses.py and what each skill's own
    prompt_generator.py actually produces -- every real risk must have a
    REAL gloss, not silently fall back to the 'not written yet' message."""
    test_cases = [
        "jailbreaking", "sensitive_info", "output_handling", "unbounded_consumption",
        "hidden_context", "vector_embedding", "excessive_agency", "misinformation",
    ]
    missing = []
    for tc_key in test_cases:
        prompts = skill_modules(tc_key)["prompt_generator"].build_prompts(
            "test objective", {"tool_use_hints": ["t"], "attachment_hints": ["a"]},
        )
        for p in prompts:
            gloss = get_layman_gloss(tc_key, p["risk_id"])
            if "no plain-english gloss written yet" in gloss.lower():
                missing.append((tc_key, p["risk_id"], p["risk_name"]))
    assert missing == [], f"missing layman glosses: {missing}"
