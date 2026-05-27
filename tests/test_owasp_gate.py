"""Tests for the Promptfoo OWASP cloud-auth gate handling.

Promptfoo's redteam/OWASP generator is a hosted feature: without
`promptfoo auth login` it stops at an email-verification prompt. That is an
auth gate, not a broken toolchain, so the orchestrator must report the step as
a SKIP with guidance rather than an errored/NOT_RUN failure.
"""
from __future__ import annotations

# A trimmed copy of the real non-interactive failure output.
GATED_OUTPUT = (
    "Generating test cases...\n"
    "Email Verification Required\n"
    "Red team scans require email verification to continue.\n"
    "? Work email:"
)
NORMAL_OUTPUT = "Running 4 test cases...\n3 passed, 1 failed\nEval complete"


def test_auth_gate_detector(orchestrator):
    assert orchestrator._is_promptfoo_auth_gated(GATED_OUTPUT)
    # The remote-generation-disabled variant is also a gate.
    assert orchestrator._is_promptfoo_auth_gated(
        "ascii-smuggling plugin requires remote generation, which has been disabled"
    )
    assert not orchestrator._is_promptfoo_auth_gated(NORMAL_OUTPUT)
    assert not orchestrator._is_promptfoo_auth_gated("")


def test_gated_skip_classifies_with_guidance(orchestrator):
    step = {
        "name": "owasp", "command": "...", "output": GATED_OUTPUT,
        "status": "skipped", "returncode": 1, "duration": 2.1,
    }
    status, severity, notes = orchestrator.classify(step)
    assert status == "skipped"
    assert severity == "NOT_RUN"
    joined = " ".join(notes).lower()
    assert "promptfoo auth login" in joined


def test_gated_step_not_listed_as_incomplete(orchestrator):
    """A cloud-auth skip must not appear in the 'steps did not complete' rec,
    but should add the dedicated OWASP-enable recommendation."""
    step = {
        "name": "owasp", "command": "...", "output": GATED_OUTPUT,
        "status": "skipped", "returncode": 1, "duration": 2.1,
    }
    layers = {"Layer 2 — Targeted": {"Promptfoo — OWASP LLM Top-10": step}}
    titles = [t for t, _ in orchestrator._recommendations(layers)]
    assert any("OWASP" in t for t in titles)
    assert not any("did not complete" in t for t in titles)


def test_owasp_command_cannot_hang_on_prompt(orchestrator):
    """The OWASP invocation must redirect stdin so the email prompt gets EOF
    and fails fast instead of hanging until the step timeout."""
    import inspect
    src = inspect.getsource(orchestrator.layer2_targeted)
    assert "redteam run" in src
    assert "</dev/null" in src
