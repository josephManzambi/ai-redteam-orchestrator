"""Unit tests for `classify` severity logic."""
from __future__ import annotations


def _step(output: str = "", status: str = "completed", returncode: int = 0) -> dict:
    return {
        "name": "x",
        "command": "x",
        "output": output,
        "status": status,
        "returncode": returncode,
        "duration": 0.0,
    }


def test_completed_with_passwd_leak_is_critical(orchestrator):
    s = _step(output="root:x:0:0:root:/root:/bin/bash")
    status, sev, _ = orchestrator.classify(s)
    assert status == "completed"
    assert sev == "CRITICAL"


def test_completed_with_uid_leak_is_critical(orchestrator):
    s = _step(output="uid=0(root) gid=0(root)")
    _, sev, _ = orchestrator.classify(s)
    assert sev == "CRITICAL"


def test_completed_with_jailbreak_marker_is_high(orchestrator):
    s = _step(output="jailbreak success on attempt 4")
    _, sev, _ = orchestrator.classify(s)
    assert sev == "HIGH"


def test_completed_with_vulnerable_marker_is_medium(orchestrator):
    s = _step(output="server is vulnerable to path traversal")
    _, sev, _ = orchestrator.classify(s)
    assert sev == "MEDIUM"


def test_completed_clean_is_info(orchestrator):
    s = _step(output="all good, nothing flagged")
    _, sev, notes = orchestrator.classify(s)
    assert sev == "INFO"
    assert any("manual review" in n for n in notes)


def test_errored_is_not_run(orchestrator):
    s = _step(output="boom", status="errored", returncode=1)
    status, sev, notes = orchestrator.classify(s)
    assert status == "errored"
    assert sev == "NOT_RUN"
    assert any("non-zero" in n for n in notes)


def test_timed_out_is_not_run(orchestrator):
    s = _step(output="...", status="timed_out", returncode=None)
    status, sev, notes = orchestrator.classify(s)
    assert sev == "NOT_RUN"
    assert any("timed out" in n.lower() for n in notes)


def test_modulenotfound_adds_import_note(orchestrator):
    s = _step(
        output="ModuleNotFoundError: No module named 'pyrit.orchestrator'",
        status="errored",
        returncode=1,
    )
    _, _, notes = orchestrator.classify(s)
    assert any("import failure" in n.lower() for n in notes)


def test_command_not_found_adds_path_note(orchestrator):
    s = _step(output="/bin/sh: garak: command not found", status="errored", returncode=127)
    _, _, notes = orchestrator.classify(s)
    assert any("PATH" in n for n in notes)
