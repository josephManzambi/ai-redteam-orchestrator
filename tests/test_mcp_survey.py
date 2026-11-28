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


# --- fetch -----------------------------------------------------------------------------

fetch = _load("fetch", STUDY / "fetch.py")
UNTIL = "2026-11-27T20:13:37Z"
API = "https://api.github.com"


def _tar(members: list[tuple]) -> bytes:
    """A gzipped archive from (name, content | None, kind) rows."""
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            else:
                info.type = {"dir": tarfile.DIRTYPE, "symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[kind]
                info.linkname = content or ""
                tar.addfile(info)
    return buf.getvalue()


class FakeGitHub:
    """Answers by URL prefix and remembers every call with its headers."""

    def __init__(self, routes: dict):
        self.routes, self.calls = routes, []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        for prefix, answer in self.routes.items():
            if url.startswith(prefix):
                status, head, body = answer
                return status, head, body if isinstance(body, bytes) else json.dumps(body).encode()
        return 404, {}, b'{"message": "Not Found"}'


def _repo(**over):
    return {"full_name": "Acme/Tools", "id": 7, "default_branch": "main", "archived": False, "fork": False,
            "private": False, "visibility": "public", "disabled": False, **over}


COMMIT = [{"sha": "a" * 40, "commit": {"committer": {"date": "2026-11-20T10:00:00Z"}}}]


def test_the_snapshot_instant_is_the_latest_publication_time_in_the_committed_snapshot():
    assert fetch.snapshot_instant([{"publishedAt": "2026-11-01T00:00:00.5Z"}, {"publishedAt": "2026-11-02T03:04:05.999Z"}, {}]) == "2026-11-02T03:04:05Z"
    assert fetch.snapshot_instant(frame.load(STUDY / "frame" / "registry-latest-2026-11-27.jsonl.gz")) == UNTIL


def test_fetch_takes_the_commit_at_the_snapshot_and_unpacks_plain_files_only(tmp_path):
    archive = _tar([("acme-tools-aaaaaaa", None, "dir"),
                    ("acme-tools-aaaaaaa/src/server.ts", b'server.tool("a", "b", {}, f)', "file"),
                    ("acme-tools-aaaaaaa/README.md", b"hello", "file"),
                    ("acme-tools-aaaaaaa/link", "/etc/passwd", "symlink"),
                    ("acme-tools-aaaaaaa/hard", "acme-tools-aaaaaaa/README.md", "hardlink"),
                    ("acme-tools-aaaaaaa/pipe", None, "fifo"),
                    ("acme-tools-aaaaaaa/../../escape.txt", b"x", "file"),
                    ("/abs/escape.txt", b"x", "file")])
    gh = FakeGitHub({f"{API}/repos/acme/tools/commits": (200, {}, COMMIT),
                     f"{API}/repos/acme/tools/tarball/": (302, {"location": "https://codeload.github.com/acme/tools/legacy.tar.gz/" + "a" * 40}, b""),
                     "https://codeload.github.com/": (200, {}, archive),
                     f"{API}/repos/acme/tools": (200, {}, _repo())})
    row = fetch.fetch_repository("acme/tools", tmp_path / "out", {"acme/tools"}, UNTIL, transport=gh, token="tok-123")
    assert row["status"] == "fetched" and row["reason"] is None
    assert row["sha"] == "a" * 40 and row["commit_date"] == "2026-11-20T10:00:00Z" and row["snapshot_instant"] == UNTIL
    assert row["files"] == 2 and row["bytes"] == len(b'server.tool("a", "b", {}, f)') + 5
    assert row["left_out"] == {"links": 2, "special": 1, "outside": 2, "over_limit": 0}
    assert sorted(p.relative_to(tmp_path / "out").as_posix() for p in (tmp_path / "out").rglob("*") if p.is_file()) == ["README.md", "src/server.ts"]
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path.parent / "escape.txt").exists()
    # The commit asked for is the last one on the default branch up to the snapshot.
    commits_call = next(u for u, _ in gh.calls if "/commits?" in u)
    assert "sha=main" in commits_call and "until=2026-11-27T20%3A13%3A37Z" in commits_call and "per_page=1" in commits_call
    # The token goes to the API and never to the archive host.
    for url, headers in gh.calls:
        assert ("Authorization" in headers) == url.startswith(API)
        assert headers["User-Agent"].startswith("mcp-descriptor-survey/")
    # The extractor reads what was unpacked.
    assert extract.extract_repository(tmp_path / "out")["static"] == 1


@pytest.mark.parametrize("answer, status, reason", [
    ((404, {}, {"message": "Not Found"}), "unavailable", "not found"),
    ((451, {}, {}), "unavailable", "blocked for legal reasons"),
    ((500, {}, {}), "unavailable", "GitHub answered 500"),
    ((200, {}, _repo(private=True, visibility="private")), "unavailable", "not public"),
    ((200, {}, _repo(disabled=True)), "unavailable", "disabled"),
    ((200, {}, _repo(archived=True)), "excluded", "archived"),
])
def test_a_repository_that_cannot_be_read_or_is_archived_is_not_downloaded(tmp_path, answer, status, reason):
    gh = FakeGitHub({f"{API}/repos/acme/tools": answer})
    row = fetch.fetch_repository("acme/tools", tmp_path / "out", set(), UNTIL, transport=gh)
    assert (row["status"], row["reason"]) == (status, reason)
    assert len(gh.calls) == 1 and not (tmp_path / "out").exists()


@pytest.mark.parametrize("commits, reason", [
    ((409, {}, {"message": "Git Repository is empty."}), "empty repository"),
    ((200, {}, []), "no commit on the default branch at the snapshot"),
    ((502, {}, {}), "commit list answered 502"),
])
def test_a_repository_with_no_commit_at_the_snapshot_is_unavailable(tmp_path, commits, reason):
    gh = FakeGitHub({f"{API}/repos/acme/tools/commits": commits, f"{API}/repos/acme/tools": (200, {}, _repo())})
    row = fetch.fetch_repository("acme/tools", tmp_path / "out", set(), UNTIL, transport=gh)
    assert (row["status"], row["reason"]) == ("unavailable", reason)


def _fork_routes(ahead):
    return {f"{API}/repos/acme/tools/commits": (200, {}, COMMIT),
            f"{API}/repos/up/stream/compare/": ahead,
            f"{API}/repos/acme/tools": (200, {}, _repo(fork=True, parent={"full_name": "Up/Stream", "default_branch": "dev/main"}))}


def test_a_fork_is_a_mirror_only_if_its_parent_is_listed_and_it_adds_no_commit():
    mirror = FakeGitHub(_fork_routes((200, {}, {"ahead_by": 0, "behind_by": 12})))
    row = fetch.describe("acme/tools", {"up/stream", "acme/tools"}, UNTIL, transport=mirror)
    assert (row["status"], row["reason"], row["ahead_of_parent"]) == ("excluded", "mirror fork of up/stream", 0)
    # The comparison is the parent's default branch against the fork's snapshot commit.
    assert any(u == f"{API}/repos/up/stream/compare/dev%2Fmain...acme:{'a' * 40}" for u, _ in mirror.calls)

    changed = FakeGitHub(_fork_routes((200, {}, {"ahead_by": 3})))
    row = fetch.describe("acme/tools", {"up/stream"}, UNTIL, transport=changed)
    assert (row["status"], row["ahead_of_parent"], row["parent"]) == ("ok", 3, "up/stream")

    unlisted = FakeGitHub(_fork_routes((200, {}, {"ahead_by": 0})))
    row = fetch.describe("acme/tools", {"someone/else"}, UNTIL, transport=unlisted)
    assert row["status"] == "ok" and row["ahead_of_parent"] is None
    assert not any("/compare/" in u for u, _ in unlisted.calls)

    unknown = FakeGitHub(_fork_routes((404, {}, {})))
    row = fetch.describe("acme/tools", {"up/stream"}, UNTIL, transport=unknown)
    assert row["status"] == "ok" and row["ahead_of_parent"] == "compare answered 404"


def test_a_renamed_repository_is_followed_on_the_api_host_only():
    gh = FakeGitHub({f"{API}/repos/old/name": (301, {"location": f"{API}/repositories/7"}, b""),
                     f"{API}/repositories/7": (200, {}, _repo(full_name="New/Name")),
                     f"{API}/repos/new/name/commits": (200, {}, COMMIT)})
    row = fetch.describe("old/name", set(), UNTIL, transport=gh)
    assert (row["status"], row["repository"], row["full_name"], row["id"]) == ("ok", "old/name", "new/name", 7)
    elsewhere = FakeGitHub({f"{API}/repos/old/name": (301, {"location": "https://example.org/x"}, b"")})
    assert fetch.describe("old/name", set(), UNTIL, transport=elsewhere)["reason"] == "GitHub answered 301"
    assert len(elsewhere.calls) == 1


def test_the_rate_limit_stops_the_fetch_and_records_nothing():
    gh = FakeGitHub({f"{API}/repos/acme/tools": (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1795900000"}, {"message": "rate limit"})})
    with pytest.raises(fetch.RateLimited, match="1795900000"):
        fetch.describe("acme/tools", set(), UNTIL, transport=gh)


def test_the_archive_must_come_from_githubs_archive_host_and_fit_the_limit(monkeypatch):
    away = FakeGitHub({f"{API}/repos/a/b/tarball/": (302, {"location": "https://codeload.github.com.example.org/x"}, b"")})
    with pytest.raises(RuntimeError, match="outside"):
        fetch.download("a/b", "c" * 40, transport=away)
    assert len(away.calls) == 1
    monkeypatch.setattr(fetch, "MAX_ARCHIVE_BYTES", 10)
    big = FakeGitHub({f"{API}/repos/a/b/tarball/": (302, {"location": "https://codeload.github.com/a/b"}, b""),
                      "https://codeload.github.com/": (200, {}, b"x" * 11)})
    assert fetch.download("a/b", "c" * 40, transport=big) is None


def test_unpack_refuses_a_folder_that_is_not_empty_and_stops_at_the_size_limit(tmp_path, monkeypatch):
    (tmp_path / "used").mkdir()
    (tmp_path / "used" / "x").write_text("x")
    with pytest.raises(RuntimeError, match="not empty"):
        fetch.unpack(_tar([("top/a", b"1", "file")]), tmp_path / "used")
    monkeypatch.setattr(fetch, "MAX_UNPACKED_BYTES", 5)
    out = fetch.unpack(_tar([("top/a", b"1234", "file"), ("top/b", b"5678", "file"), ("top/c", b"9", "file")]), tmp_path / "new")
    assert (out["files"], out["bytes"], out["left_out"]["over_limit"]) == (2, 5, 1)


def test_fetch_is_refused_for_a_frame_repository_until_the_protocol_is_tagged(monkeypatch, capsys, tmp_path):
    sys.path.insert(0, str(STUDY))
    try:
        survey = _load("survey_fetch", STUDY / "survey.py")
    finally:
        sys.path.remove(str(STUDY))
    in_frame = next(iter(frame.build(frame.load(survey.latest_snapshot()))))
    monkeypatch.setattr(survey, "protocol_is_tagged", lambda: False)
    monkeypatch.setattr(survey.fetch, "fetch_repository", lambda *a, **k: pytest.fail("a frame repository was fetched"))
    assert survey.main(["survey.py", "fetch", in_frame, str(tmp_path / "out")]) == 3
    assert "not tagged" in capsys.readouterr().err
    # A repository outside the frame can be fetched, which is how the tool is tried out.
    monkeypatch.setattr(survey.fetch, "fetch_repository", lambda repo, dest, frame_repos, until, token=None: {"repository": repo, "until": until})
    assert survey.main(["survey.py", "fetch", "Octocat/Hello-World", str(tmp_path / "out")]) == 0
    assert json.loads(capsys.readouterr().out) == {"repository": "octocat/hello-world", "until": UNTIL}
