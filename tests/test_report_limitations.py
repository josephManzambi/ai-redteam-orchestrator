"""The generated report must carry the project's own limitations.

Issues #27-#34 document real boundaries — self-play scoring, heuristic
severity, trimmed scope, version drift. Before this, all of that lived in the
README and the issue tracker, so it never travelled with the artifact a reader
actually receives. A report that asserts severities without stating their basis
is the same false assurance the npm `mcp-scan` evidence in this repo documents.
"""
from __future__ import annotations

import os

import pytest


def _layers(*commands: str) -> dict:
    """Minimal layers structure with the given step commands."""
    return {
        "Layer X": {
            f"step {i}": {
                "status": "completed", "returncode": 0, "output": "ok",
                "command": cmd, "duration": 1.0,
            }
            for i, cmd in enumerate(commands)
        }
    }


def test_unconditional_limitations_always_present(orchestrator):
    # Even a run with no recognisable tool states the four core boundaries.
    got = {t for t, _ in orchestrator._limitations(_layers("echo hello"))}
    assert "A clean run is a smoke test, not an assessment" in got
    assert "Severity is heuristic, with false-negative risk" in got
    assert "Scope is trimmed for laptop-grade targets" in got
    assert "Toolchain version drift is load-bearing" in got


def test_self_play_limitation_only_when_pyrit_ran(orchestrator):
    self_play = "The same model is target, attacker and judge"
    without = {t for t, _ in orchestrator._limitations(_layers("garak --probes x"))}
    assert self_play not in without

    with_pyrit = {t for t, _ in orchestrator._limitations(
        _layers("uv run python attack_pyrit_crescendo.py"))}
    assert self_play in with_pyrit


def test_promptfoo_and_mcp_limitations_are_conditional(orchestrator):
    pf = "Promptfoo's OWASP generation is cloud-gated"
    mcp = "MCP coverage is static and single-server"

    got = {t for t, _ in orchestrator._limitations(_layers("garak --probes x"))}
    assert pf not in got and mcp not in got

    got = {t for t, _ in orchestrator._limitations(
        _layers("npx promptfoo@latest eval", "uv run mcp_descriptor_scan.py"))}
    assert pf in got and mcp in got


def test_no_limitation_has_an_empty_body(orchestrator):
    for title, body in orchestrator._limitations(
            _layers("pyrit", "promptfoo", "mcp_descriptor_scan")):
        assert title.strip(), "limitation with no title"
        assert len(body.strip()) > 40, f"limitation {title!r} has a stub body"


def test_markdown_report_contains_limitations(orchestrator, tmp_path, monkeypatch):
    md = tmp_path / "report.md"
    monkeypatch.setattr(orchestrator, "REPORT_FILE_MD", str(md))
    orchestrator.write_report_md(_layers("uv run python attack_pyrit_tap.py"))
    text = md.read_text()
    assert "## Limitations" in text
    assert "smoke test" in text.lower()
    # The pointer must appear before the summary a reader would act on.
    assert text.index("Read [Limitations]") < text.index("## Executive Summary")
    # And the section must precede the recommendations drawn from the findings.
    assert text.index("## Limitations") < text.index("## Recommendations")
    assert "target, attacker and judge" in text


def test_html_report_contains_limitations(orchestrator, tmp_path, monkeypatch):
    html = tmp_path / "report.html"
    monkeypatch.setattr(orchestrator, "REPORT_FILE_HTML", str(html))
    orchestrator.write_report_html(_layers("npx promptfoo@latest eval"))
    text = html.read_text()
    assert "id='limitations'" in text
    assert "cloud-gated" in text
    assert text.index("Read <a href='#limitations'>") < text.index("<h2 id='limitations'>")
    assert text.index("<h2 id='limitations'>") < text.index("<h2>Recommendations</h2>")
