"""Regression tests for issue #35: the Markdown report must not let raw model
output break out of its code fence.

The HTML report escapes output; the Markdown report wraps it in a backtick
fence. Model (i.e. attacker-influenced) output that contains its own fence, a
heading, or an image link must stay *inside* one fenced block so it cannot
inject structure into a trusted-looking audit document.
"""
from __future__ import annotations

import re

import pytest


# A payload that tries three distinct break-out tricks at once.
FENCE_ATTEMPT = "```"
HEADING_ATTEMPT = "# EVIL INJECTED HEADING"
IMAGE_ATTEMPT = "![pwn](http://evil.example/x.png)"
ADVERSARIAL_OUTPUT = (
    "harmless preamble\n"
    f"{FENCE_ATTEMPT}\n"
    f"{HEADING_ATTEMPT}\n"
    f"{IMAGE_ATTEMPT}\n"
    "trailing text with a stray ```` run too\n"
)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("no backticks here", "```"),
        ("one ` tick", "```"),
        ("two `` ticks", "```"),
        ("a fence ``` inside", "````"),
        ("````", "`````"),
        ("mixed ``` then ````` longest wins", "``````"),
    ],
)
def test_fence_for_outgrows_longest_run(orchestrator, text, expected):
    fence = orchestrator._fence_for(text)
    assert fence == expected
    # The fence must be strictly longer than any backtick run in the body.
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    assert len(fence) > longest
    assert len(fence) >= 3


def _raw_output_region(md: str) -> str:
    """Return the text between the Raw-output <summary> and its </details>."""
    start = md.index("<summary>Raw output</summary>")
    end = md.index("</details>", start)
    return md[start:end]


def test_markdown_report_contains_adversarial_output_without_breakout(orchestrator, tmp_path, monkeypatch):
    report = tmp_path / "RedTeam_Report.md"
    monkeypatch.setattr(orchestrator, "REPORT_FILE_MD", str(report))

    layers = {
        "Layer 1 — Broad Scan": {
            "Adversarial step": {
                "output": ADVERSARIAL_OUTPUT,
                "status": "completed",
                "command": "echo adversarial",
                "duration": 1.0,
            }
        }
    }
    orchestrator.write_report_md(layers)

    md = report.read_text()
    region = _raw_output_region(md)

    # All three break-out attempts survive verbatim inside the block.
    assert HEADING_ATTEMPT in region
    assert IMAGE_ATTEMPT in region
    assert FENCE_ATTEMPT in region

    # Find the fence delimiter the renderer chose (first all-backtick line).
    fence_lines = [ln for ln in region.splitlines() if re.fullmatch(r"`+", ln.strip())]
    assert fence_lines, "no fenced block found in raw-output region"
    fence = fence_lines[0]

    # It must have adapted past the default ``` because the payload holds a 3-run.
    assert len(fence) >= 4

    # Exactly two lines equal the fence delimiter: the opener and the closer.
    # (A premature close would create a third, or the payload's own run would
    # match — either breaks this count.)
    exact = [ln for ln in region.splitlines() if ln.strip() == fence]
    assert len(exact) == 2, f"expected one open + one close fence, got {len(exact)}"

    # The closing fence comes after every break-out marker: the payload is
    # wholly contained in the single block.
    close_pos = region.rindex(fence)
    for marker in (FENCE_ATTEMPT, HEADING_ATTEMPT, IMAGE_ATTEMPT):
        assert region.index(marker) < close_pos
