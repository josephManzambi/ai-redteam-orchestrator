"""Unit tests for `run_step` exit-code handling.

These regressions cost real time during local runs:
- promptfoo exits 100 when assertions fail (signal, not error).
- mcp-scan exits non-zero when its JSON report contains findings.
Both were tagged "errored" before the fix; these tests pin the contract.
"""
from __future__ import annotations

import subprocess
from types import SimpleNamespace


def _completed(rc: int, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


def test_zero_exit_is_completed(orchestrator, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(0, "ok"))
    r = orchestrator.run_step("clean", "echo ok", timeout=5)
    assert r["status"] == "completed"
    assert r["returncode"] == 0
    assert "ok" in r["output"]


def test_nonzero_exit_is_errored_for_arbitrary_command(orchestrator, monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _completed(1, "", "boom")
    )
    r = orchestrator.run_step("broken", "some_random_tool", timeout=5)
    assert r["status"] == "errored"
    assert r["returncode"] == 1
    assert "boom" in r["output"]


def test_promptfoo_rc100_is_completed(orchestrator, monkeypatch):
    """promptfoo exits 100 when assertions fail — that's a finding, not a failure."""
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: _completed(100, "2 failed (50%)", ""),
    )
    r = orchestrator.run_step(
        "broad", "npx -y promptfoo@latest eval --config promptfoo_broad.json", timeout=5
    )
    assert r["status"] == "completed"
    assert r["returncode"] == 100
    assert "assertions failed" in r["output"]


def test_promptfoo_rc1_is_still_errored(orchestrator, monkeypatch):
    """Only rc=100 should be reclassified — rc=1 from promptfoo is a real error."""
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _completed(1, "", "config error")
    )
    r = orchestrator.run_step(
        "broad", "npx -y promptfoo@latest eval", timeout=5
    )
    assert r["status"] == "errored"


def test_mcp_scan_nonzero_with_findings_is_completed(orchestrator, monkeypatch):
    payload = '{"results": [{"serverName": "x"}], "totalScanned": 1, "highCount": 1}'
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1, payload, ""))
    r = orchestrator.run_step(
        "scan", "npx -y mcp-scan@latest scan -c x.json --json", timeout=5
    )
    assert r["status"] == "completed"
    assert "findings produced" in r["output"]


def test_mcp_scan_nonzero_without_json_is_errored(orchestrator, monkeypatch):
    """Non-zero with no scan JSON means the scanner itself blew up."""
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _completed(1, "", "ENOENT: x.json")
    )
    r = orchestrator.run_step(
        "scan", "npx -y mcp-scan@latest scan -c missing.json --json", timeout=5
    )
    assert r["status"] == "errored"


def test_timeout_is_timed_out(orchestrator, monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=k.get("timeout", 1))

    monkeypatch.setattr(subprocess, "run", boom)
    r = orchestrator.run_step("slow", "sleep 9999", timeout=1)
    assert r["status"] == "timed_out"
    assert r["returncode"] is None
    assert "TIMEOUT" in r["output"]


def test_exec_error_is_exec_error(orchestrator, monkeypatch):
    def boom(*a, **k):
        raise OSError("kernel said no")

    monkeypatch.setattr(subprocess, "run", boom)
    r = orchestrator.run_step("nope", "x", timeout=5)
    assert r["status"] == "exec_error"
    assert "kernel said no" in r["output"]
