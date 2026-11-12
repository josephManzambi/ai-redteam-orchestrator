"""--judge-model: a separate PyRIT scorer so the target does not grade itself (#27)."""
from __future__ import annotations

import ast

import pytest


@pytest.fixture
def judge(orchestrator, monkeypatch):
    def set_models(target, judge_model):
        monkeypatch.setattr(orchestrator.cfg, "model", target)
        monkeypatch.setattr(orchestrator.cfg, "judge_model", judge_model)
    return set_models


@pytest.mark.parametrize("gen", ["_pyrit_crescendo_script", "_pyrit_tap_script"])
def test_scorer_uses_judge_model(orchestrator, judge, gen):
    judge("qwen2.5:7b-instruct-q8_0", "mistral:7b")
    src = getattr(orchestrator, gen)()
    ast.parse(src)
    assert '_ollama_target("mistral:7b")' in src
    # target and adversarial chat stay on the target model
    assert 'def _ollama_target(model="qwen2.5:7b-instruct-q8_0")' in src


@pytest.mark.parametrize("gen", ["_pyrit_crescendo_script", "_pyrit_tap_script"])
def test_default_is_self_play(orchestrator, judge, gen):
    judge("qwen2.5:7b-instruct-q8_0", None)
    src = getattr(orchestrator, gen)()
    assert '_ollama_target("qwen2.5:7b-instruct-q8_0")' in src


def test_independence_needs_a_different_family(orchestrator, judge):
    judge("qwen2.5:7b-instruct-q8_0", "mistral:7b")
    assert orchestrator._judge_independent()
    judge("qwen2.5:7b-instruct-q8_0", "qwen3:8b")
    assert not orchestrator._judge_independent()
    judge("qwen2.5:7b-instruct-q8_0", None)
    assert not orchestrator._judge_independent()


def _pyrit_layers():
    return {"L3": {"PyRIT": {"command": "uv run python attack_pyrit_crescendo.py",
                             "output": "", "status": "completed"}}}


def test_limitation_follows_the_judge(orchestrator, judge):
    judge("qwen2.5:7b-instruct-q8_0", None)
    titles = [t for t, _ in orchestrator._limitations(_pyrit_layers())]
    assert "The same model is target, attacker and judge" in titles

    judge("qwen2.5:7b-instruct-q8_0", "mistral:7b")
    titles = [t for t, _ in orchestrator._limitations(_pyrit_layers())]
    assert "The same model is target, attacker and judge" not in titles
    assert "The attacker is still the target model" in titles


def test_header_names_the_judge(orchestrator, judge):
    judge("qwen2.5:7b-instruct-q8_0", "mistral:7b")
    assert "separate family" in orchestrator._report_header()["judge_model"]
    judge("qwen2.5:7b-instruct-q8_0", None)
    assert "self-play" in orchestrator._report_header()["judge_model"]
