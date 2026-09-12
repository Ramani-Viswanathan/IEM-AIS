"""
Shared fixtures for the IEM-AIS test suite. No network calls anywhere in
this suite -- classifiers are pure functions of (risk_id, response_text,
...) and are tested with canned strings, not live model replies.

Reuses ui/server.py's own module loader (_get_test_case_modules) instead
of re-implementing it, so tests exercise the exact same prompt_generator/
inject binding path the real UI uses -- including the sys.modules
collision guard CLAUDE.md documents (four skills' inject.py/
prompt_generator.py share filenames but must never bind to each other's).
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ui" / "shared"))

spec = importlib.util.spec_from_file_location("iem_server", ROOT / "ui" / "server.py")
iem_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iem_server)

import inject_base  # noqa: E402 -- needs ui/shared on sys.path first (see above)


def skill_modules(test_case):
    """{"inject": <module>, "prompt_generator": <module>} for one of
    ui/server.py's registered TEST_CASES keys, correctly isolated from
    every other skill's same-named modules. Cached by iem_server itself."""
    return iem_server._get_test_case_modules(test_case)
