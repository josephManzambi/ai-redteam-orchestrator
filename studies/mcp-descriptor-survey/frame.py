"""The sampling frame of the MCP descriptor survey (PROTOCOL.md, "Sampling frame").

From a compact registry snapshot (frame/snapshot_registry.py) to the eligible
repositories: servers that are active, have a public GitHub repository and an
npm or PyPI package. The unit is the repository, so a monorepo that lists many
servers is one row.

Archived repositories and forks that only mirror another listed server are
also excluded by the protocol, but that needs GitHub's API and is checked when
the sample is walked, not here.
"""
from __future__ import annotations

import gzip
import json
import re
from collections import Counter
from pathlib import Path

# The author's own projects are out of the frame (PROTOCOL.md, Exclusion).
AUTHOR_OWNERS = ("josephmanzambi",)
PACKAGE_STRATA = {"npm": "typescript", "pypi": "python"}
_GITHUB = re.compile(r"^(?:https?://|git\+https://|git://|git@|ssh://git@)?(?:www\.)?github\.com[/:]([^/\s]+)/([^/\s#?]+)", re.I)


def repo_key(url: str | None) -> str | None:
    """'owner/name' in lower case for a GitHub URL, None for anything else."""
    if not url:
        return None
    m = _GITHUB.match(url.strip())
    if not m:
        return None
    owner, name = m.group(1), m.group(2)
    name = re.sub(r"\.git$", "", name, flags=re.I)
    if not owner or not name:
        return None
    return f"{owner}/{name}".lower()


def load(path: str | Path) -> list[dict]:
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def package_types(record: dict) -> set[str]:
    return {(p.get("registryType") or "").lower() for p in (record.get("packages") or [])} & set(PACKAGE_STRATA)


def eligible(record: dict) -> bool:
    return record.get("status") == "active" and repo_key(record.get("repository")) is not None and bool(package_types(record))


def build(records: list[dict], exclude_owners: tuple[str, ...] = AUTHOR_OWNERS) -> dict[str, dict]:
    """{repository: {"stratum": "typescript"|"python", "servers": [names]}}.

    A repository's language stratum follows its registry entries: npm packages
    are TypeScript, PyPI packages are Python. A repository listed with both
    goes where most of its entries are; a tie goes to TypeScript.
    """
    by_repo: dict[str, dict] = {}
    for rec in records:
        if not eligible(rec):
            continue
        key = repo_key(rec["repository"])
        if key.split("/")[0] in exclude_owners:
            continue
        row = by_repo.setdefault(key, {"servers": [], "types": Counter()})
        row["servers"].append(rec["name"])
        for t in package_types(rec):
            row["types"][t] += 1
    frame = {}
    for key in sorted(by_repo):
        types = by_repo[key]["types"]
        stratum = "python" if types["pypi"] > types["npm"] else "typescript"
        frame[key] = {"stratum": stratum, "servers": sorted(by_repo[key]["servers"])}
    return frame


def counts(records: list[dict]) -> dict[str, int]:
    """The table in FRAME-CHECK.md, from the snapshot alone."""
    active = [r for r in records if r.get("status") == "active"]
    with_repo = [r for r in active if repo_key(r.get("repository"))]
    with_pkg = [r for r in with_repo if package_types(r)]
    frame = build(records)
    return {
        "servers": len(records),
        "active": len(active),
        "active_no_repository_url": sum(1 for r in active if not r.get("repository")),
        "active_github": len(with_repo),
        "active_github_npm_or_pypi": len(with_pkg),
        "entries_npm": sum(1 for r in with_pkg if "npm" in package_types(r)),
        "entries_pypi": sum(1 for r in with_pkg if "pypi" in package_types(r)),
        "repositories": len(frame),
        "repositories_typescript": sum(1 for v in frame.values() if v["stratum"] == "typescript"),
        "repositories_python": sum(1 for v in frame.values() if v["stratum"] == "python"),
    }
