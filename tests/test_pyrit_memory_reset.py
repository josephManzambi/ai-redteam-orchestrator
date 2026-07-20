"""Regression tests for issue #36: PyRIT memory is reset before a Layer-3 run.

PyRIT persists conversation memory in ~/.pyrit between runs, so a stale
transcript can colour today's scoring. The orchestrator clears it by default
before Layer 3, with an opt-out, and stamps the outcome into the report.
"""
from __future__ import annotations

import pytest


def test_reset_fires_when_layer3_selected_and_fresh(orchestrator, monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "_clean_pyrit_state", lambda: calls.append(True))

    status = orchestrator._maybe_reset_pyrit_memory({1, 2, 3}, fresh=True)

    assert calls == [True], "cleanup helper must be invoked once"
    assert status == "reset"


def test_no_reset_when_layer3_not_selected(orchestrator, monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "_clean_pyrit_state", lambda: calls.append(True))

    status = orchestrator._maybe_reset_pyrit_memory({1, 2}, fresh=True)

    assert calls == [], "cleanup must not run when Layer 3 is out of scope"
    assert status.startswith("n/a")


def test_opt_out_preserves_memory(orchestrator, monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "_clean_pyrit_state", lambda: calls.append(True))

    status = orchestrator._maybe_reset_pyrit_memory({3}, fresh=False)

    assert calls == [], "--no-fresh-pyrit-memory must skip the reset"
    assert status.startswith("reused")


def test_status_is_stamped_into_report_header(orchestrator, monkeypatch):
    monkeypatch.setattr(orchestrator.cfg, "pyrit_memory", "reset", raising=False)
    header = orchestrator._report_header()
    assert header.get("pyrit_memory") == "reset"
