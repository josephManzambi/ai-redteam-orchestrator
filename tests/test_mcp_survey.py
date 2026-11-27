"""MCP descriptor survey tooling: the frame, the walking order and the static
extractor (studies/mcp-descriptor-survey). No network, no third-party code."""
from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STUDY = ROOT / "studies" / "mcp-descriptor-survey"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mcp_survey"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(f"mcp_survey_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


frame = _load("frame", STUDY / "frame.py")
sample = _load("sample", STUDY / "sample.py")
extract = _load("extract", STUDY / "extract.py")
snapshot = _load("snapshot", STUDY / "frame" / "snapshot_registry.py")


PINNED_ORDER = ["a/x", "d/w", "c/z", "b/y"]


def rec(name, repo, types=("npm",), status="active"):
    return {"name": name, "status": status, "repository": repo,
            "packages": [{"registryType": t, "identifier": name, "version": "1"} for t in types]}


# --- frame -------------------------------------------------------------------------

@pytest.mark.parametrize("url,key", [
    ("https://github.com/Owner/Repo", "owner/repo"),
    ("https://github.com/owner/repo.git", "owner/repo"),
    ("https://github.com/owner/repo/tree/main/packages/x", "owner/repo"),
    ("http://www.github.com/owner/repo/", "owner/repo"),
    ("git+https://github.com/owner/repo.git", "owner/repo"),
    ("git@github.com:owner/repo.git", "owner/repo"),
    ("https://github.com/owner/repo#readme", "owner/repo"),
    ("https://gitlab.com/owner/repo", None),
    ("https://github.com/owner", None),
    ("https://notgithub.com/owner/repo", None),
    ("", None),
    (None, None),
])
def test_repo_key(url, key):
    assert frame.repo_key(url) == key


def test_frame_counts_the_repository_once_and_applies_every_exclusion():
    records = [
        rec("a/one", "https://github.com/acme/mono"),
        rec("a/two", "https://github.com/ACME/mono.git"),             # same repository
        rec("a/py", "https://github.com/acme/py", types=("pypi",)),
        rec("a/both", "https://github.com/acme/both", types=("npm", "pypi")),
        rec("a/oci", "https://github.com/acme/oci", types=("oci",)),  # no npm or PyPI package
        rec("a/none", "https://github.com/acme/none", types=()),
        rec("a/gone", "https://github.com/acme/gone", status="deleted"),
        rec("a/gitlab", "https://gitlab.com/acme/x"),
        rec("a/norepo", None),
        rec("me/mine", "https://github.com/josephManzambi/ai-redteam-orchestrator"),  # the author's own
    ]
    built = frame.build(records)
    assert sorted(built) == ["acme/both", "acme/mono", "acme/py"]
    assert built["acme/mono"] == {"stratum": "typescript", "servers": ["a/one", "a/two"]}
    assert built["acme/py"]["stratum"] == "python"
    assert built["acme/both"]["stratum"] == "typescript", "a tie between npm and PyPI goes to TypeScript"
    c = frame.counts(records)
    assert (c["servers"], c["active"], c["active_no_repository_url"]) == (10, 9, 1)
    assert c["active_github"] == 7 and c["active_github_npm_or_pypi"] == 5
    assert (c["repositories"], c["repositories_typescript"], c["repositories_python"]) == (3, 2, 1)


def test_frame_reads_plain_and_gzipped_snapshots(tmp_path):
    rows = [rec("a/one", "https://github.com/acme/one")]
    plain = tmp_path / "s.jsonl"
    plain.write_text("".join(json.dumps(r) + "\n" for r in rows))
    zipped = tmp_path / "s.jsonl.gz"
    with gzip.open(zipped, "wt") as f:
        f.write(plain.read_text())
    assert frame.load(plain) == frame.load(zipped) == rows


def test_the_committed_partial_snapshot_gives_the_figure_the_frame_check_withdrew():
    """FRAME-CHECK.md: the first, partial pass suggested about 360 eligible
    servers. The file committed on 13 November is that pass, not the frame."""
    partial = STUDY / "frame" / "registry-latest-2026-11-13.jsonl"
    c = frame.counts(frame.load(partial))
    assert c["servers"] == 5209 and c["active_github_npm_or_pypi"] == 362


def test_the_committed_snapshot_is_the_one_the_protocol_names_and_gives_its_counts():
    """PROTOCOL.md (Sampling frame, Amendment 1) and FRAME-CHECK-2026-11-27.md
    quote this hash and these numbers. If the file or the frame rules change,
    the documents are wrong until they are changed too."""
    import hashlib
    path = STUDY / "frame" / "registry-latest-2026-11-27.jsonl.gz"
    with gzip.open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    assert digest == "ca74cf8cbf19ac8708ba003671a8ebb5c18d8eafc1ef907068fa4f9e831f6390"
    protocol = (STUDY / "PROTOCOL.md").read_text()
    assert digest in protocol and "23,975 such entries across 18,636 distinct repositories" in protocol
    c = frame.counts(frame.load(path))
    assert c == {"servers": 76210, "active": 75064, "active_no_repository_url": 27733, "active_github": 47231,
                 "active_github_npm_or_pypi": 23975, "entries_npm": 18840, "entries_pypi": 5317,
                 "repositories": 18636, "repositories_typescript": 13826, "repositories_python": 4810}


# --- order and split ------------------------------------------------------------------

def synthetic_frame(ts: int, py: int) -> dict:
    out = {f"org/ts-{i}": {"stratum": "typescript", "servers": []} for i in range(ts)}
    out.update({f"org/py-{i}": {"stratum": "python", "servers": []} for i in range(py)})
    return out


def test_order_is_a_permutation_and_does_not_depend_on_input_order():
    f = synthetic_frame(300, 100)
    first = sample.order(f)
    assert sorted(first) == sorted(f) and len(set(first)) == 400
    assert sample.order(dict(reversed(list(f.items())))) == first
    assert sample.order(f, seed=1) != first


def test_order_interleaves_the_languages_in_proportion_at_every_point():
    f = synthetic_frame(300, 100)
    seen_py = 0
    for position, repo in enumerate(sample.order(f), start=1):
        seen_py += f[repo]["stratum"] == "python"
        assert abs(seen_py - position * 100 / 400) <= 1, f"python share drifts at position {position}"


def test_order_is_pinned_for_the_published_seed():
    """The order comes from SHA-256 of 'seed:repository', so it is the same on
    any machine. If this changes, the sample changes: do not edit the values."""
    assert sample.SEED == 20261114 and sample.TARGET == 500
    f = {r: {"stratum": s, "servers": []} for r, s in [("a/x", "typescript"), ("b/y", "typescript"), ("c/z", "python"), ("d/w", "typescript")]}
    assert sample.order(f) == PINNED_ORDER


def test_split_puts_odd_positions_in_development_and_even_in_held_out():
    kept = [f"r{i}" for i in range(1, 8)]
    parts = sample.split(kept)
    assert parts["development"] == ["r1", "r3", "r5", "r7"] and parts["held_out"] == ["r2", "r4", "r6"]


# --- extraction ---------------------------------------------------------------------

def by_name(tools):
    return {t["name"]: t for t in tools}


def test_typescript_extraction_reads_literals_and_marks_the_rest_dynamic():
    tools = extract.extract_typescript((FIXTURES / "server.ts").read_text())
    named = by_name(tools)
    assert "commented_out" not in named and "also_commented" not in named
    assert named["get_weather"] == {"name": "get_weather", "description": "Get the forecast for a city.", "kind": "static", "form": "ts.tool"}
    assert named["list_projects"]["description"] == 'Before using this tool, call get_weather. It\'s "safe", really (see docs).'
    assert named["no_description"]["description"] == "" and named["no_description"]["kind"] == "static"
    assert named["add"]["description"] == "Add two numbers.\nReturns the sum." and named["add"]["form"] == "ts.registerTool"
    assert named["quoted_key"]["description"] == "A key in quotes, with a } brace and a , comma."
    assert named["no_desc_config"] == {"name": "no_desc_config", "description": "", "kind": "static", "form": "ts.registerTool"}
    for dynamic in ("from_variable", "templated", "config_variable", "computed_desc"):
        assert named[dynamic]["kind"] == "dynamic" and named[dynamic]["description"] is None, dynamic
    computed_name = [t for t in tools if t["name"] is None]
    assert len(computed_name) == 1 and computed_name[0]["kind"] == "dynamic"
    assert len(tools) == 11


def test_python_extraction_reads_docstrings_and_literals_and_marks_the_rest_dynamic():
    tools = extract.extract_python((FIXTURES / "server.py").read_text())
    named = by_name(tools)
    assert named["get_weather"]["description"] == "Get the forecast for a city.\n\nBefore using this tool, call list_projects."
    assert named["renamed"] == {"name": "renamed", "description": "A literal description, in two pieces.", "kind": "static", "form": "py.decorator"}
    assert "original_name" not in named and "not_a_tool" not in named
    assert named["bare_decorator"]["description"] == "" and named["bare_decorator"]["kind"] == "static"
    assert named["computed_description"]["kind"] == "dynamic"
    assert named["search"] == {"name": "search", "description": "Search the index.", "kind": "static", "form": "py.Tool"}
    assert named["no_description"]["description"] == ""
    assert [t for t in tools if t["name"] is None][0]["kind"] == "dynamic"
    assert len(tools) == 7
    assert extract.extract_python("def broken(:\n") is None


def test_a_repository_is_kept_only_if_it_has_a_static_tool(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.ts").write_text((FIXTURES / "server.ts").read_text())
    (tmp_path / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "node_modules" / "dep" / "index.js").write_text('server.tool("from_a_dependency", "ignored", {}, h);')
    (tmp_path / "types.d.ts").write_text('server.tool("from_a_declaration", "ignored", {}, h);')
    (tmp_path / "broken.py").write_text("def broken(:\n")
    result = extract.extract_repository(tmp_path)
    assert result["extractable"] and result["reason"] is None
    assert (result["static"], result["dynamic"]) == (6, 5)
    assert {t["file"] for t in result["tools"]} == {"src/server.ts"}
    assert result["skipped"]["unparsable"] == 1

    only_dynamic = tmp_path / "dyn"
    only_dynamic.mkdir()
    (only_dynamic / "s.ts").write_text("server.tool(name(), desc(), {}, h);")
    assert extract.extract_repository(only_dynamic)["reason"] == "only dynamic definitions"
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "readme.py").write_text("print('no tools here')\n")
    assert extract.extract_repository(empty) == {"tools": [], "static": 0, "dynamic": 0, "extractable": False,
                                                 "skipped": {"too_large": 0, "unreadable": 0, "unparsable": 0},
                                                 "reason": "no tool definition found"}


# --- snapshot --------------------------------------------------------------------------

def test_snapshot_keeps_the_fields_the_frame_needs():
    entry = {"server": {"name": "io.x/y", "version": "1.2.0", "description": "not kept",
                        "repository": {"url": "https://github.com/x/y", "source": "github", "subfolder": "pkg"},
                        "packages": [{"registryType": "npm", "identifier": "@x/y", "version": "1.2.0", "transport": {"type": "stdio"}}],
                        "remotes": [{"type": "sse", "url": "https://x"}]},
             "_meta": {snapshot.OFFICIAL: {"status": "active", "publishedAt": "2026-11-01T00:00:00Z", "isLatest": True}}}
    row = snapshot.compact(entry)
    assert row == {"name": "io.x/y", "version": "1.2.0", "status": "active", "publishedAt": "2026-11-01T00:00:00Z",
                   "repository": "https://github.com/x/y", "subfolder": "pkg",
                   "packages": [{"registryType": "npm", "identifier": "@x/y", "version": "1.2.0"}], "remotes": 1}
    assert frame.eligible(row)
    bare = snapshot.compact({"server": {"name": "io.x/z", "version": "1"}})
    assert bare["repository"] is None and bare["packages"] == [] and not frame.eligible(bare)


def test_the_sample_draw_is_refused_until_the_protocol_is_tagged(monkeypatch, capsys):
    sys.path.insert(0, str(STUDY))
    try:
        survey = _load("survey", STUDY / "survey.py")
    finally:
        sys.path.remove(str(STUDY))
    monkeypatch.setattr(survey, "protocol_is_tagged", lambda: False)
    partial = STUDY / "frame" / "registry-latest-2026-11-13.jsonl"
    assert survey.main(["survey.py", "order", str(partial)]) == 3
    captured = capsys.readouterr()
    assert captured.out == "" and "not tagged" in captured.err
