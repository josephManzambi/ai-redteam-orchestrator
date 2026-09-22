"""Pin the Garak probe names the orchestrator depends on.

Issue #33: toolchain version drift is load-bearing, and Garak carries no
version pin. It has already renamed a probe once (`xss` -> `web_injection` in
0.14), and the README then described three *surviving* probes as renamed or
removed for months afterwards. A wrong claim about the toolchain is the kind
of error this project's own evidence directory is about.

These tests skip when Garak is not installed, so CI stays fast; they run
wherever Garak is present, which is where the drift would actually be seen.
"""
from __future__ import annotations

import importlib

import pytest

garak = pytest.importorskip("garak", reason="Garak not installed in this env")


def _probe_module_exists(name: str) -> bool:
    try:
        importlib.import_module(f"garak.probes.{name}")
        return True
    except ImportError:
        return False


# Named in layer1_broad_scan()'s `probes` list. If one of these disappears the
# scan silently covers less than it claims.
REQUIRED = ["latentinjection", "dan", "goodside"]

# Documented in the README as deliberately omitted. They must still EXIST —
# the README's previous claim that they were "renamed or removed" was wrong
# for all three, and that is the assertion worth pinning.
OMITTED_BUT_PRESENT = ["glitch", "malwaregen", "leakreplay", "promptinject"]


@pytest.mark.parametrize("name", REQUIRED)
def test_required_probe_modules_exist(name):
    assert _probe_module_exists(name), (
        f"garak.probes.{name} is gone. layer1_broad_scan() names it, so the "
        f"broad scan now covers less than the report will claim."
    )


@pytest.mark.parametrize("name", OMITTED_BUT_PRESENT)
def test_omitted_probes_still_exist(name):
    assert _probe_module_exists(name), (
        f"garak.probes.{name} no longer exists. The README says it is omitted "
        f"by choice rather than gone — update that wording."
    )


def test_xss_was_renamed_to_web_injection():
    # The one claim in the README that was true. Pin both halves so a future
    # reader does not have to re-derive it.
    assert not _probe_module_exists("xss"), "garak.probes.xss is back; README is stale"
    assert _probe_module_exists("web_injection"), "web_injection is gone; README is stale"


def test_readme_does_not_claim_surviving_probes_were_removed():
    """Guard the specific wrong sentence, not just the underlying facts."""
    from pathlib import Path
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    assert "leakreplay) was renamed or removed" not in readme, (
        "The README again describes surviving probes as renamed or removed."
    )
