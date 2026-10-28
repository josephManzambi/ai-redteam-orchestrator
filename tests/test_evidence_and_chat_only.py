"""Chat-only PyRIT grading, per-run evidence files, and --skip-owasp."""
from __future__ import annotations

PASSWD = "root:x:0:0:root:/root:/bin/bash"


def _step(output, command):
    return {"name": "x", "command": command, "output": output,
            "status": "completed", "returncode": 0, "duration": 0.0}


def test_pyrit_passwd_text_is_not_critical(orchestrator):
    s = _step(f"assistant: example output: {PASSWD}",
              "uv run python attack_pyrit_crescendo.py")
    _, sev, notes = orchestrator.classify(s)
    assert sev != "CRITICAL"
    assert any("chat-only" in n for n in notes)


def test_pyrit_success_phrase_still_high(orchestrator):
    s = _step(f"ATTACK SUCCEEDED — objective achieved.\n{PASSWD}",
              "uv run python attack_pyrit_crescendo.py")
    _, sev, _ = orchestrator.classify(s)
    assert sev == "HIGH"


def test_non_pyrit_passwd_is_still_critical(orchestrator):
    _, sev, _ = orchestrator.classify(_step(PASSWD, "uv run garak"))
    assert sev == "CRITICAL"


def test_save_step_evidence_writes_full_output(orchestrator, tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, "EVIDENCE_DIR", str(tmp_path))
    big = "A" * 50000
    layers = {"L": {"PyRIT — Crescendo escalation": _step(big, "x")}}
    orchestrator.save_step_evidence(layers, "run1")
    step = layers["L"]["PyRIT — Crescendo escalation"]
    assert step["evidence_path"].endswith("pyrit-crescendo-escalation.txt")
    assert open(step["evidence_path"]).read() == big


def test_report_links_evidence_when_truncated(orchestrator, tmp_path):
    import io
    step = _step("B" * 20000, "x")
    step["evidence_path"] = "evidence/runs/r/s.txt"
    buf = io.StringIO()
    orchestrator._md_section(buf, "S", step)
    assert "evidence/runs/r/s.txt" in buf.getvalue()


def test_skip_owasp_returns_skipped_step_without_running(orchestrator, monkeypatch):
    monkeypatch.setattr(orchestrator.cfg, "skip_owasp", True)
    monkeypatch.setattr(orchestrator.cfg, "mcp_config", None)
    monkeypatch.setattr(orchestrator.cfg, "demo_server", False)
    monkeypatch.setattr(orchestrator, "run_step",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    out = orchestrator.layer2_targeted()
    step = out["Promptfoo — OWASP LLM Top-10"]
    assert step["status"] == "skipped"
    status, sev, _ = orchestrator.classify(step)
    assert sev == "NOT_RUN"
