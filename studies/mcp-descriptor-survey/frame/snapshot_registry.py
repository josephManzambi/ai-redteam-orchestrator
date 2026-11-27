#!/usr/bin/env python3
"""Snapshot the official MCP Registry listing: the latest version of every server.

Metadata only. No server or package is downloaded or run. One request per page
of 100, a pause between pages, a generic client name (PROTOCOL.md, Ethics).

Writes two files next to this script:
  registry-latest-<date>.jsonl.gz   compact, sorted by name, committed
  raw/registry-latest-<date>.jsonl  the API's own records, not committed

and prints the SHA-256 of each, so the exact snapshot can be identified.

    python3 frame/snapshot_registry.py            # today's date in the file name
    python3 frame/snapshot_registry.py --date 2026-11-27
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HOST = "registry.modelcontextprotocol.io"
CLIENT = "mcp-descriptor-survey/1.0 (registry metadata only)"
PAGE = 100          # the API's maximum
PAUSE = 0.25        # seconds between pages
OFFICIAL = "io.modelcontextprotocol.registry/official"


def use_direct_dns_if_needed(host: str = HOST) -> None:
    """Some resolvers fail on this host while a direct DNS query answers. If the
    system lookup fails, ask DNS directly and use that address for this host
    only. TLS still checks the certificate against the host name."""
    try:
        socket.getaddrinfo(host, 443)
        return
    except socket.gaierror:
        pass
    out = subprocess.run(["dig", "+short", host], capture_output=True, text=True, timeout=20).stdout.split()
    ips = [x for x in out if x.replace(".", "").isdigit()]
    if not ips:
        raise SystemExit(f"cannot resolve {host}")
    real = socket.getaddrinfo

    def patched(name, *args, **kwargs):
        return real(ips[0] if name == host else name, *args, **kwargs)

    socket.getaddrinfo = patched


def get_page(cursor: str | None) -> dict:
    query = {"limit": PAGE, "version": "latest"}
    if cursor:
        query["cursor"] = cursor
    url = f"https://{HOST}/v0/servers?{urllib.parse.urlencode(query)}"
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": CLIENT, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as res:
                return json.load(res)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
            if attempt == 5:
                raise SystemExit(f"gave up on {url}: {err}")
            time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def compact(entry: dict) -> dict:
    """The fields the frame needs, in a fixed shape."""
    server = entry.get("server", {})
    meta = (entry.get("_meta") or {}).get(OFFICIAL, {})
    repo = server.get("repository") or {}
    return {
        "name": server.get("name"),
        "version": server.get("version"),
        "status": meta.get("status"),
        "publishedAt": meta.get("publishedAt"),
        "repository": repo.get("url") or None,
        "subfolder": repo.get("subfolder") or None,
        "packages": [
            {"registryType": p.get("registryType"), "identifier": p.get("identifier"), "version": p.get("version")}
            for p in (server.get("packages") or [])
        ],
        "remotes": len(server.get("remotes") or []),
    }


def sha256(path: Path, unzip: bool = False) -> str:
    h = hashlib.sha256()
    with (gzip.open(path, "rb") if unzip else open(path, "rb")) as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--date", default=dt.date.today().isoformat())
    args = ap.parse_args()
    here = Path(__file__).resolve().parent
    raw_path = here / "raw" / f"registry-latest-{args.date}.jsonl"
    out_path = here / f"registry-latest-{args.date}.jsonl.gz"
    raw_path.parent.mkdir(exist_ok=True)
    use_direct_dns_if_needed()

    rows: dict[str, dict] = {}
    cursor, pages = None, 0
    with open(raw_path, "w", encoding="utf-8") as raw:
        while True:
            page = get_page(cursor)
            for entry in page.get("servers", []):
                raw.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
                row = compact(entry)
                if row["name"]:
                    rows[row["name"]] = row
            pages += 1
            cursor = (page.get("metadata") or {}).get("nextCursor")
            if pages % 50 == 0:
                print(f"  {pages} pages, {len(rows)} servers", file=sys.stderr)
            if not cursor or not page.get("servers"):
                break
            time.sleep(PAUSE)

    # Sorted, one record per line, gzip with no timestamp: the same listing always
    # gives the same bytes.
    body = "".join(json.dumps(rows[n], sort_keys=True, separators=(",", ":")) + "\n" for n in sorted(rows))
    with open(out_path, "wb") as f, gzip.GzipFile(fileobj=f, mode="wb", mtime=0) as gz:
        gz.write(body.encode("utf-8"))

    print(f"servers (latest version each): {len(rows)} in {pages} pages")
    print(f"compact file: {out_path.name}")
    print(f"  SHA-256 of its uncompressed content: {sha256(out_path, unzip=True)}")
    print(f"raw file (not committed): raw/{raw_path.name}")
    print(f"  SHA-256: {sha256(raw_path)}")


if __name__ == "__main__":
    main()
