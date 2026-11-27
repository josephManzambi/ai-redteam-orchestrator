# MCP descriptor survey: frame check (27 November 2026)

**Status: a count of the sampling frame, not Phase 1.** No sample has been drawn and nothing has been extracted. This file replaces the numbers in `FRAME-CHECK.md` (13 November), whose snapshot was not kept. `PROTOCOL.md`, Amendment 1, says why.

## What was done
The official registry's listing was read through its public API with `frame/snapshot_registry.py`: the latest version of every server, 100 per page, a pause between pages, a generic client name. Metadata only. No server or package was downloaded or run.

Two files came out of it:

| File | Size | SHA-256 | Committed |
|---|---|---|---|
| `frame/registry-latest-2026-11-27.jsonl.gz` (one line per server, sorted by name, the fields the frame needs) | 2.4 MB | of its uncompressed content: `ca74cf8cbf19ac8708ba003671a8ebb5c18d8eafc1ef907068fa4f9e831f6390` | yes |
| `frame/raw/registry-latest-2026-11-27.jsonl` (the API's own records) | 69 MB | `96d8d60979d237df40567b6ffe4bdf9732d09c463d30ee3792b2ce6b57446efb` | no |

The committed file is the frame's source. The raw file is kept on the author's machine only; its hash is here so it can be recognised.

## Counts, latest version of each server

Reproduce with `python3 survey.py counts`.

| | 27 November | 13 November (not kept) |
|---|---|---|
| Distinct servers (latest version each) | 76,210 | 63,406 |
| of which status `active` | 75,064 | 62,406 |
| active, with no repository URL | 27,733 | 22,212 |
| active, with a GitHub repository | 47,231 | 40,101 |
| active, GitHub repository and an npm or PyPI package | **23,975** (npm 18,840; PyPI 5,317) | 20,289 (npm 15,544; PyPI 4,906) |
| distinct GitHub repositories behind those | **18,636** | 17,232 |
| of which TypeScript (npm) | 13,826 | not recorded |
| of which Python (PyPI) | 4,810 | not recorded |

182 eligible entries list both an npm and a PyPI package, so the npm and PyPI figures add up to more than 23,975.

## What this means for the protocol
- **The registry grew by a fifth in two weeks** (63,406 to 76,210 servers). A frame is only a frame if its snapshot is kept, which is why the compact file is committed this time.
- **A sample of 500 is under 3% of the 18,636 repositories**, as before.
- **Counting by repository matters more than it looked.** 305 repositories list more than one server, and one of them lists 3,511. Sampling registry entries would have drawn that one codebase again and again.
- **Most entries have nothing to sample.** 27,733 active entries have no repository at all, and 23,256 more have a GitHub repository but no npm or PyPI package.
- **Archived repositories and mirror forks are still in these counts.** The protocol excludes them, but that needs GitHub's API and is checked as the sample is walked.

## Not decided here
The second labeller and the protocol's reviewer are still the author's to name (decisions 4 and 5). The sample is not drawn until then: `python3 survey.py order` refuses to run without the protocol tag.
