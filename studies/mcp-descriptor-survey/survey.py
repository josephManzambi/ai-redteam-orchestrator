#!/usr/bin/env python3
"""MCP descriptor survey: the commands behind PROTOCOL.md.

    python3 survey.py counts  [snapshot]    the frame's size, from a registry snapshot
    python3 survey.py order   [snapshot]    the order repositories are walked in
    python3 survey.py extract <folder>      tools found in one checked-out repository
    python3 survey.py fetch <owner/name> <folder>
                                            one repository's source at the snapshot commit

`order` is the sample draw. The protocol says the sample is not drawn until the
protocol is tagged, and it is tagged only once a reviewer's comments are in the
history or the reviewer has declined in writing. So `order` refuses to run
unless the git tag below exists.

`fetch` asks GitHub about one repository, applies the protocol's exclusions and
unpacks the source at the commit current at the snapshot. Nothing from the
repository is run. For a repository of the frame it refuses until the same tag
exists, so no sampled repository is read early. Set GITHUB_TOKEN to use an
authenticated rate limit; without it GitHub allows 60 requests an hour.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import extract
import fetch
import frame
import sample

HERE = Path(__file__).resolve().parent
PROTOCOL_TAG = "mcp-survey-protocol-v1"


def latest_snapshot() -> Path:
    found = sorted((HERE / "frame").glob("registry-latest-*.jsonl.gz"))
    if not found:
        raise SystemExit("no snapshot in frame/: run frame/snapshot_registry.py first")
    return found[-1]


def protocol_is_tagged() -> bool:
    out = subprocess.run(["git", "-C", str(HERE), "tag", "--list", PROTOCOL_TAG], capture_output=True, text=True)
    return PROTOCOL_TAG in out.stdout.split()


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("counts", "order", "extract", "fetch"):
        print(__doc__)
        return 2
    if argv[1] == "extract":
        if len(argv) < 3:
            raise SystemExit("extract needs a folder")
        result = extract.extract_repository(argv[2])
        # Descriptor text is the server author's: print counts and names only.
        print(json.dumps({k: result[k] for k in ("static", "dynamic", "skipped", "extractable", "reason")}, indent=2))
        for t in result["tools"]:
            print(f"  {t['kind']:7} {t['form']:13} {t['name']!r:40} {t['file']}")
        return 0
    if argv[1] == "fetch":
        if len(argv) < 4:
            raise SystemExit("fetch needs a repository (owner/name) and an empty folder")
        repo = frame.repo_key("https://github.com/" + argv[2])
        if repo is None:
            raise SystemExit("fetch needs a repository written as owner/name")
        records = frame.load(latest_snapshot())
        frame_repos = set(frame.build(records))
        if repo in frame_repos and not protocol_is_tagged():
            print(f"Refusing to fetch {repo}: it is in the frame and the protocol is not tagged ({PROTOCOL_TAG}).\n"
                  "No repository of the frame is read before the draw (PROTOCOL.md, decision 5).", file=sys.stderr)
            return 3
        try:
            row = fetch.fetch_repository(repo, argv[3], frame_repos, fetch.snapshot_instant(records),
                                         token=os.environ.get("GITHUB_TOKEN") or None)
        except fetch.RateLimited as err:
            print(str(err), file=sys.stderr)
            return 4
        print(json.dumps(row, indent=2))
        return 0
    snapshot = Path(argv[2]) if len(argv) > 2 else latest_snapshot()
    records = frame.load(snapshot)
    if argv[1] == "counts":
        print(f"snapshot: {snapshot.name}")
        for key, value in frame.counts(records).items():
            print(f"  {key:28} {value:>7,}")
        return 0
    if not protocol_is_tagged():
        print(f"Refusing to draw the sample: the protocol is not tagged ({PROTOCOL_TAG}).\n"
              "PROTOCOL.md, decision 5: the sample is drawn only after the reviewer's comments\n"
              "are in the history or the reviewer has declined in writing.", file=sys.stderr)
        return 3
    for position, repo in enumerate(sample.order(frame.build(records)), start=1):
        print(f"{position}\t{repo}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
