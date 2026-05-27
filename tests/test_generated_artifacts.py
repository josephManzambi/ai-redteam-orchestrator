"""Regression tests for the artifacts the orchestrator writes to disk.

Catches the kinds of drift that bit us during local runs:
- generated PyRIT scripts must parse and reference symbols that exist in
  the pinned PyRIT version
- generated promptfoo configs must round-trip through json.dumps and
  point Promptfoo's grader at a local provider (not the OpenAI fallback)
"""
from __future__ import annotations

import ast
import importlib
import json

import pytest


# ---------------- PyRIT generated scripts ----------------

PYRIT_SYMBOLS_REQUIRED = {
    "pyrit.common": ["initialize_pyrit", "IN_MEMORY"],
    "pyrit.orchestrator": [
        "CrescendoOrchestrator",
        "TreeOfAttacksWithPruningOrchestrator",
    ],
    "pyrit.prompt_target": ["OpenAIChatTarget"],
}


@pytest.mark.parametrize("generator_name", ["_pyrit_crescendo_script", "_pyrit_tap_script"])
def test_generated_pyrit_script_parses(orchestrator, generator_name):
    src = getattr(orchestrator, generator_name)()
    ast.parse(src)  # raises SyntaxError on drift in the template


def test_generated_pyrit_script_uses_openai_target_not_ollama(orchestrator):
    """PyRIT 0.8 dropped OllamaChatTarget — make sure we never regenerate it.

    Match against actual usage (`from ... import` and `(`) rather than the
    bare name, so explanatory comments mentioning the old class don't
    trigger a false positive.
    """
    for fn in (orchestrator._pyrit_crescendo_script, orchestrator._pyrit_tap_script):
        src = fn()
        assert "import OllamaChatTarget" not in src, (
            "OllamaChatTarget was removed in PyRIT 0.8 — generated script must not import it"
        )
        assert "OllamaChatTarget(" not in src, (
            "OllamaChatTarget was removed in PyRIT 0.8 — generated script must not call it"
        )
        assert "OpenAIChatTarget" in src
        assert "11434" in src, "must point at the local Ollama OpenAI-compatible endpoint"


def test_pyrit_pinned_version_exposes_required_symbols():
    """Smoke-check the pinned PyRIT install — would fail if 0.8.1 ever drifts.

    Skipped automatically if PyRIT is not installed in the test env (the
    GitHub workflow installs it explicitly; local `pytest` without the
    extras shouldn't fail noisily).
    """
    try:
        for module_name, symbols in PYRIT_SYMBOLS_REQUIRED.items():
            mod = importlib.import_module(module_name)
            for s in symbols:
                assert hasattr(mod, s), f"{module_name}.{s} missing"
    except ImportError:
        pytest.skip("pyrit not installed in this environment")


def test_tap_tree_shape_fits_laptop_budget(orchestrator):
    """Guard against accidentally re-bloating TAP back to the unrunnable defaults."""
    src = orchestrator._pyrit_tap_script()
    # Grep the kwargs out of the generated source.
    assert "width=2" in src
    assert "depth=2" in src
    assert "branching_factor=2" in src
    assert "on_topic_checking_enabled=False" in src


# ---------------- Promptfoo generated configs ----------------

def test_promptfoo_broad_config_is_json_serializable(orchestrator):
    cfg = orchestrator._promptfoo_broad_config()
    json.dumps(cfg)  # raises TypeError on non-serializable keys
    assert cfg["providers"], "must declare at least one provider"


def test_promptfoo_broad_grader_is_local_not_openai(orchestrator):
    """Without defaultTest.options.provider, llm-rubric falls back to OpenAI."""
    cfg = orchestrator._promptfoo_broad_config()
    grader = cfg.get("defaultTest", {}).get("options", {}).get("provider")
    assert grader, "defaultTest.options.provider must be set to keep evals offline"
    assert "openai" not in grader.lower()


def test_promptfoo_owasp_config_scope_fits_default_timeout(orchestrator):
    """Trim was deliberate — guard against re-bloating to the timing-out scope."""
    cfg = orchestrator._promptfoo_owasp_config()
    rt = cfg["redteam"]
    assert rt["numTests"] <= 2, "numTests > 2 timed out on a laptop 7B"
    assert len(rt["plugins"]) <= 5
    assert len(rt["strategies"]) <= 3


def test_garak_default_probe_set_is_broad_and_shallow(orchestrator):
    """Layer 1 must stay a broad, shallow scan that fits its timeout.

    The full/heavy probe set timed out, so guard the design: many categories
    (breadth) at depth 1, with the known-heavy probes kept out. Parse only the
    quoted probe specs inside the `",".join([...])` list so explanatory
    comments (which may mention old names like `xss`) don't trip the checks.
    """
    import inspect, re
    src = inspect.getsource(orchestrator.layer1_broad_scan)
    block = re.search(r'\.join\(\[(.*?)\]\)', src, re.S)
    assert block, "could not find the `\",\".join([...])` probe list"
    probes = set(re.findall(r'"([^"]+)"', block.group(1)))
    assert probes, "probe list is empty"

    # Breadth: indirect injection stays covered, and many categories are hit.
    assert any(p.startswith("latentinjection") for p in probes)
    categories = {p.split(".")[0] for p in probes}
    assert len(categories) >= 6, f"too few categories for a broad scan: {categories}"

    # Shallow depth: one generation per prompt, attempts parallelized.
    assert "--generations 1" in src
    assert "--parallel_attempts" in src

    # The known-heavy probes that blew the timeout must stay out.
    assert not any("DanInTheWild" in p or "Ablation" in p or "AutoDAN" in p for p in probes)
    assert "promptinject" not in categories
    # Families removed/renamed in Garak 0.14 must not appear as bare specs.
    assert "xss" not in probes
    assert "glitch" not in probes


# ---------------- mcp-scan invocation ----------------

def test_mcp_scan_invocation_uses_dash_c_flag(orchestrator):
    """`scan` takes the config via `-c <path>` — the positional form silently scans 0 servers."""
    import inspect
    src = inspect.getsource(orchestrator.layer2_targeted)
    assert "scan -c " in src, "mcp-scan config path must be passed via -c"
