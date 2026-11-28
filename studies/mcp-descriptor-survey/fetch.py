"""Fetching one repository for the MCP descriptor survey (PROTOCOL.md,
"Sampling frame" and "Extraction").

For one repository this module does three things, in this order:

1. asks GitHub's public API whether the repository can be read and whether the
   protocol excludes it (archived, or a fork that only mirrors another listed
   repository);
2. finds the commit that was current on the default branch at the snapshot;
3. downloads the source at that commit as an archive and unpacks it.

Nothing from the repository is run: no clone, no hooks, no install. The archive
is unpacked file by file, and anything that is not a plain file inside the
target folder is left out.

This module fetches the one repository it is given. It does not walk the
sample: that is `survey.py order`, which stays locked until the protocol is
tagged.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import shutil
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

API = "https://api.github.com"
ARCHIVE_HOST = "codeload.github.com"
CLIENT = "mcp-descriptor-survey/1.0 (public repository metadata and source)"
# An archive larger than this is not unpacked. The extractor reads source
# files of at most 1 MB each, so a repository this large is mostly not source.
MAX_ARCHIVE_BYTES = 300_000_000
MAX_UNPACKED_BYTES = 1_000_000_000
MAX_MEMBERS = 200_000

# (status, headers with lower-case names, body)
Response = tuple
Transport = Callable[[str, dict], Response]


class RateLimited(RuntimeError):
    """GitHub's rate limit is used up. Nothing is recorded for the repository:
    the caller waits and asks again."""


def snapshot_instant(records: list[dict]) -> str:
    """The moment the snapshot stands for: the latest publication time in it,
    to the second, in UTC. It is read from the committed snapshot, so anyone
    with the file gets the same instant."""
    latest = max(r["publishedAt"] for r in records if r.get("publishedAt"))
    return latest[:19] + "Z"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # the caller follows redirects itself
        return None


def http_transport(url: str, headers: dict) -> Response:
    """One GET, redirects not followed. The body is read up to the archive
    limit plus one byte, so an oversized archive is seen and not kept."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=120) as res:
            return res.status, {k.lower(): v for k, v in res.headers.items()}, res.read(MAX_ARCHIVE_BYTES + 1)
    except urllib.error.HTTPError as err:
        return err.code, {k.lower(): v for k, v in err.headers.items()}, err.read(2_000_000)


def _headers(token: str | None) -> dict:
    h = {"User-Agent": CLIENT, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _api(transport: Transport, path: str, token: str | None, hops: int = 3) -> tuple[int, dict, object]:
    """One API call. A renamed repository answers with a redirect to another
    API address: that is followed, on api.github.com only."""
    url = API + path
    for _ in range(hops):
        status, headers, body = transport(url, _headers(token))
        if status in (301, 302, 307, 308) and headers.get("location", "").startswith(API + "/"):
            url = headers["location"]
            continue
        break
    if status in (403, 429) and headers.get("x-ratelimit-remaining") == "0":
        raise RateLimited(f"GitHub rate limit used up; it resets at {headers.get('x-ratelimit-reset', 'an unknown time')} (Unix time)")
    try:
        data = json.loads(body.decode("utf-8")) if body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        data = None
    return status, headers, data


def _unavailable(repo: str, reason: str, **extra) -> dict:
    return {"repository": repo, "status": "unavailable", "reason": reason, **extra}


def describe(repo: str, frame_repos: set[str], until: str, transport: Transport = http_transport, token: str | None = None) -> dict:
    """What GitHub says about one repository, and whether the protocol keeps it.

    status is "ok" (can be fetched), "excluded" (the protocol leaves it out) or
    "unavailable" (it cannot be read). reason says why for the last two.
    """
    owner, name = repo.split("/", 1)
    status, _, meta = _api(transport, f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}", token)
    if status == 404:
        return _unavailable(repo, "not found")
    if status == 451:
        return _unavailable(repo, "blocked for legal reasons")
    if status != 200 or not isinstance(meta, dict):
        return _unavailable(repo, f"GitHub answered {status}")
    row = {
        "repository": repo,
        "full_name": (meta.get("full_name") or "").lower(),
        "id": meta.get("id"),
        "default_branch": meta.get("default_branch"),
        "archived": bool(meta.get("archived")),
        "fork": bool(meta.get("fork")),
        "parent": None,
        "ahead_of_parent": None,
    }
    if meta.get("private") or meta.get("visibility") not in (None, "public"):
        return {**row, "status": "unavailable", "reason": "not public"}
    if meta.get("disabled"):
        return {**row, "status": "unavailable", "reason": "disabled"}
    if row["archived"]:
        return {**row, "status": "excluded", "reason": "archived"}

    branch = row["default_branch"]
    q = urllib.parse.urlencode({"sha": branch or "", "until": until, "per_page": 1})
    status, _, commits = _api(transport, f"/repos/{row['full_name']}/commits?{q}", token)
    if status == 409:
        return {**row, "status": "unavailable", "reason": "empty repository"}
    if status != 200 or not isinstance(commits, list):
        return {**row, "status": "unavailable", "reason": f"commit list answered {status}"}
    if not commits:
        return {**row, "status": "unavailable", "reason": "no commit on the default branch at the snapshot"}
    row["sha"] = commits[0]["sha"]
    row["commit_date"] = commits[0]["commit"]["committer"]["date"]

    # A fork that only mirrors another listed repository: its parent is in the
    # frame and, at the snapshot commit, it has no commit the parent lacks.
    parent = meta.get("parent") or {}
    if row["fork"] and parent.get("full_name"):
        row["parent"] = parent["full_name"].lower()
        if row["parent"] in frame_repos:
            base = urllib.parse.quote(parent.get("default_branch") or "HEAD", safe="")
            head = f"{urllib.parse.quote(row['full_name'].split('/')[0])}:{row['sha']}"
            status, _, cmp = _api(transport, f"/repos/{row['parent']}/compare/{base}...{head}", token)
            if status == 200 and isinstance(cmp, dict):
                row["ahead_of_parent"] = cmp.get("ahead_by")
                if row["ahead_of_parent"] == 0:
                    return {**row, "status": "excluded", "reason": f"mirror fork of {row['parent']}"}
            else:
                # Not known to be a mirror, so it is kept; the failed check is recorded.
                row["ahead_of_parent"] = f"compare answered {status}"
    return {**row, "status": "ok", "reason": None}


def download(full_name: str, sha: str, transport: Transport = http_transport, token: str | None = None) -> bytes | None:
    """The source archive at one commit, or None if it is larger than the
    limit. GitHub answers the API call with a redirect to its archive host;
    the token is not sent there, since a public archive needs none."""
    status, headers, body = transport(f"{API}/repos/{full_name}/tarball/{sha}", _headers(token))
    if status in (403, 429) and headers.get("x-ratelimit-remaining") == "0":
        raise RateLimited("GitHub rate limit used up")
    if status in (301, 302, 307, 308):
        target = headers.get("location", "")
        if urllib.parse.urlsplit(target).hostname != ARCHIVE_HOST or not target.startswith("https://"):
            raise RuntimeError("archive redirect points outside GitHub's archive host")
        status, headers, body = transport(target, {"User-Agent": CLIENT})
    if status != 200:
        raise RuntimeError(f"archive download answered {status}")
    return None if len(body) > MAX_ARCHIVE_BYTES else body


def unpack(archive: bytes, dest: str | Path) -> dict:
    """Unpack a source archive into dest, plain files only.

    GitHub puts everything under one top folder, which is dropped. A member is
    left out, and counted, if it is a link or a device, if its path would land
    outside dest, or if the size limits are passed. Nothing is made executable.
    """
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise RuntimeError(f"{dest} is not empty")
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    left_out = {"links": 0, "special": 0, "outside": 0, "over_limit": 0}
    files = total = seen = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
        for member in tar:
            seen += 1
            if seen > MAX_MEMBERS:
                left_out["over_limit"] += 1
                continue
            if member.issym() or member.islnk():
                left_out["links"] += 1
                continue
            if member.isdir():
                continue
            if not member.isfile():
                left_out["special"] += 1
                continue
            parts = Path(member.name).parts[1:]  # drop the top folder
            if not parts or member.name.startswith("/") or ".." in parts:
                left_out["outside"] += 1
                continue
            target = (root.joinpath(*parts)).resolve()
            if root != target and root not in target.parents:
                left_out["outside"] += 1
                continue
            if total + member.size > MAX_UNPACKED_BYTES:
                left_out["over_limit"] += 1
                continue
            source = tar.extractfile(member)
            if source is None:
                left_out["special"] += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, open(target, "wb") as out:
                shutil.copyfileobj(source, out)
            os.chmod(target, 0o644)
            files += 1
            total += member.size
    return {"files": files, "bytes": total, "left_out": left_out}


def fetch_repository(repo: str, dest: str | Path, frame_repos: set[str], until: str,
                     transport: Transport = http_transport, token: str | None = None) -> dict:
    """describe, then download and unpack if the repository is kept. The row
    returned is what the dataset records for it; it holds no source text."""
    row = describe(repo, frame_repos, until, transport, token)
    row["snapshot_instant"] = until
    row["fetched_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if row["status"] != "ok":
        return row
    archive = download(row["full_name"], row["sha"], transport, token)
    if archive is None:
        return {**row, "status": "unavailable", "reason": "archive larger than the limit"}
    return {**row, "status": "fetched", **unpack(archive, dest)}
