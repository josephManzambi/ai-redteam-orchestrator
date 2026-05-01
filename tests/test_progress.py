"""Tests for the live progress bar wiring.

We don't render the bar in tests — we just pin the step-count math
(_count_steps must match what the layer runners actually call run_step
for) and the run_step → progress integration (description set on entry,
advance on exit).
"""
from __future__ import annotations

from unittest.mock import patch


def test_count_steps_layer1_only(orchestrator):
    orchestrator.cfg.mcp_config = None
    orchestrator.cfg.demo_server = False
    assert orchestrator._count_steps({1}) == 2


def test_count_steps_layer2_without_mcp_target_skips_mcp_scan(orchestrator):
    orchestrator.cfg.mcp_config = None
    orchestrator.cfg.demo_server = False
    # Promptfoo OWASP runs; mcp-scan short-circuits to a skipped marker
    # without going through run_step.
    assert orchestrator._count_steps({2}) == 1


def test_count_steps_layer2_with_mcp_config_includes_mcp_scan(orchestrator):
    orchestrator.cfg.mcp_config = "/tmp/fake.json"
    orchestrator.cfg.demo_server = False
    assert orchestrator._count_steps({2}) == 2


def test_count_steps_layer2_with_demo_server_includes_mcp_scan(orchestrator):
    orchestrator.cfg.mcp_config = None
    orchestrator.cfg.demo_server = True
    assert orchestrator._count_steps({2}) == 2


def test_count_steps_layer3_only(orchestrator):
    assert orchestrator._count_steps({3}) == 2


def test_count_steps_full_run_with_mcp_config(orchestrator):
    orchestrator.cfg.mcp_config = "/tmp/fake.json"
    orchestrator.cfg.demo_server = False
    assert orchestrator._count_steps({1, 2, 3}) == 6


def test_run_step_advances_progress_on_success(orchestrator):
    """run_step must update the description and advance the bar exactly once."""
    fake_progress = type("FP", (), {})()
    fake_progress.update = lambda *a, **k: fake_progress.calls.append(("update", a, k))
    fake_progress.advance = lambda *a, **k: fake_progress.calls.append(("advance", a, k))
    fake_progress.calls = []

    orchestrator._PROGRESS = fake_progress
    orchestrator._PROGRESS_TASK_ID = 0
    try:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = type(
                "R", (), {"returncode": 0, "stdout": "ok", "stderr": ""}
            )()
            result = orchestrator.run_step("step-A", "echo hi")
        assert result["status"] == "completed"
        kinds = [c[0] for c in fake_progress.calls]
        assert kinds == ["update", "advance"], kinds
    finally:
        orchestrator._PROGRESS = None
        orchestrator._PROGRESS_TASK_ID = None


def test_run_step_advances_progress_on_timeout(orchestrator):
    """Even when the subprocess times out, progress must advance."""
    import subprocess

    fake_progress = type("FP", (), {})()
    fake_progress.update = lambda *a, **k: fake_progress.calls.append(("update", a, k))
    fake_progress.advance = lambda *a, **k: fake_progress.calls.append(("advance", a, k))
    fake_progress.calls = []

    orchestrator._PROGRESS = fake_progress
    orchestrator._PROGRESS_TASK_ID = 0
    try:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("c", 1)):
            result = orchestrator.run_step("step-T", "sleep 9999")
        assert result["status"] == "timed_out"
        assert any(c[0] == "advance" for c in fake_progress.calls)
    finally:
        orchestrator._PROGRESS = None
        orchestrator._PROGRESS_TASK_ID = None


def test_run_step_does_not_crash_when_progress_is_none(orchestrator):
    """Cleanup-path run_step calls happen with _PROGRESS=None — must not blow up."""
    orchestrator._PROGRESS = None
    orchestrator._PROGRESS_TASK_ID = None
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = type(
            "R", (), {"returncode": 0, "stdout": "ok", "stderr": ""}
        )()
        result = orchestrator.run_step("step-X", "echo hi")
    assert result["status"] == "completed"
