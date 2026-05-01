"""Regression tests for per-layer timeout overrides.

The slow steps must not be capped at --timeout below their per-layer
default. The global --timeout must still raise overrides above their
default if the user asks for more.
"""
from __future__ import annotations


def test_layer_timeouts_dict_has_expected_keys(orchestrator):
    assert "garak" in orchestrator.LAYER_TIMEOUTS
    assert "promptfoo_owasp" in orchestrator.LAYER_TIMEOUTS
    assert orchestrator.LAYER_TIMEOUTS["garak"] >= 14400
    assert orchestrator.LAYER_TIMEOUTS["promptfoo_owasp"] >= 7200


def test_step_timeout_uses_override_when_global_is_lower(orchestrator):
    orchestrator.cfg.timeout = 1800
    assert orchestrator._step_timeout("garak") == 14400
    assert orchestrator._step_timeout("promptfoo_owasp") == 7200


def test_step_timeout_uses_global_when_higher(orchestrator):
    orchestrator.cfg.timeout = 21600  # 6h
    assert orchestrator._step_timeout("garak") == 21600
    assert orchestrator._step_timeout("promptfoo_owasp") == 21600


def test_step_timeout_falls_back_to_global_for_unknown_key(orchestrator):
    orchestrator.cfg.timeout = 3600
    assert orchestrator._step_timeout("unknown") == 3600
    assert orchestrator._step_timeout(None) == 3600


def test_layer1_uses_garak_timeout(orchestrator):
    """Catch a regression where someone removes the per-layer timeout."""
    import inspect
    src = inspect.getsource(orchestrator.layer1_broad_scan)
    assert "_step_timeout" in src
    assert "garak" in src


def test_layer2_uses_promptfoo_owasp_timeout(orchestrator):
    import inspect
    src = inspect.getsource(orchestrator.layer2_targeted)
    assert "_step_timeout" in src
    assert "promptfoo_owasp" in src
