"""Tests for the OWASP coverage mapping and its renderers.

The mapping in `redteam_orchestrator.py` is the single source of truth; the
README table and the report sections render from it. These tests pin the
data shape, the renderer output, and the README copy so they cannot drift.
"""
from __future__ import annotations

from pathlib import Path

import pytest

README = Path(__file__).resolve().parents[1] / "README.md"


def _tables(orchestrator):
    return {
        "MCP": orchestrator.OWASP_MCP_TOP10,
        "LLM": orchestrator.OWASP_LLM_TOP10,
    }


def test_each_taxonomy_has_ten_entries(orchestrator):
    for table in _tables(orchestrator).values():
        assert len(table) == 10


def test_ids_are_sequential_and_prefixed(orchestrator):
    for prefix, table in _tables(orchestrator).items():
        expected = [f"{prefix}{i:02d}" for i in range(1, 11)]
        assert list(table.keys()) == expected


def test_every_entry_is_well_formed(orchestrator):
    for table in _tables(orchestrator).values():
        for rid, entry in table.items():
            assert set(entry) == {"title", "level", "by", "note"}, rid
            assert entry["title"].strip(), rid
            assert entry["level"] in orchestrator.OWASP_COVERAGE_LEVELS, rid
            # A row with real coverage must say what provides it.
            if entry["level"] != "Not covered":
                assert entry["by"].strip(), f"{rid} claims {entry['level']} but names no source"


def test_renderer_mentions_every_id(orchestrator):
    md = orchestrator.render_owasp_coverage_md()
    html = orchestrator.render_owasp_coverage_html()
    for table in _tables(orchestrator).values():
        for rid in table:
            assert rid in md
            assert rid in html


def test_readme_matches_renderer_verbatim(orchestrator):
    """The README OWASP block must be exactly what the code renders."""
    md = orchestrator.render_owasp_coverage_md()
    readme = README.read_text(encoding="utf-8")
    assert md in readme, (
        "README OWASP table is out of sync with render_owasp_coverage_md(). "
        "Regenerate it from the orchestrator and paste the output into README.md."
    )


def test_agentic_is_a_note_not_a_table(orchestrator):
    """Agentic risks are scoped out, not scored — no ASI table rows."""
    md = orchestrator.render_owasp_coverage_md()
    assert "intentionally not scored" in md
    assert "| ASI01 |" not in md


def test_command_injection_is_direct(orchestrator):
    # MCP05/Command Injection is the tool's strongest, always-on coverage.
    assert orchestrator.OWASP_MCP_TOP10["MCP05"]["level"] == "Direct"


def test_multi_agent_risks_absent_from_mcp_and_llm_tables(orchestrator):
    # Sanity: the genuinely multi-agent concerns are not smuggled into the
    # single-agent tables as covered rows.
    blob = " ".join(
        e["title"] for t in _tables(orchestrator).values() for e in t.values()
    ).lower()
    assert "inter-agent" not in blob
    assert "cascading" not in blob
