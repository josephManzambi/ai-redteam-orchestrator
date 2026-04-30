"""Load `redteam_orchestrator.py` as a module despite its uv inline-script header.

The orchestrator is shipped as a single PEP 723 script. Loading it via
`importlib.util.spec_from_file_location` lets the test suite poke at internal
helpers (`run_step`, `classify`, `_promptfoo_*_config`, the PyRIT script
generators) without spawning subprocesses.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def orchestrator():
    root = Path(__file__).resolve().parents[1]
    path = root / "redteam_orchestrator.py"
    spec = importlib.util.spec_from_file_location("redteam_orchestrator", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["redteam_orchestrator"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module
