# MCP descriptor survey

A survey of tool descriptions in public MCP servers: how often they contain the patterns scanners flag, how many of those flags are false alarms, and how often a description changes without a version change. The design is fixed in advance in [PROTOCOL.md](PROTOCOL.md).

**Where it stands (28 November 2026).** The protocol is written and amended. The frame is counted ([FRAME-CHECK-2026-11-27.md](FRAME-CHECK-2026-11-27.md)). The tools below exist and are tested. **No sample has been drawn and no repository of the frame has been fetched.** That waits for a reviewer (PROTOCOL.md, decision 5).

## Commands

Python 3.9 or later, standard library only. Nothing here runs third-party code.

```bash
python3 survey.py counts             # the frame's size, from the committed snapshot
python3 survey.py extract <folder>   # tools found in one checked-out repository
python3 survey.py order              # the sample draw: refuses until the protocol is tagged
python3 survey.py fetch <owner/name> <folder>   # one repository's source at the snapshot commit
python3 frame/snapshot_registry.py   # a new registry snapshot (a new frame: see the protocol first)
```

## Files

| File | What it does |
|---|---|
| `frame/registry-latest-2026-11-27.jsonl.gz` | the registry snapshot the frame is built from |
| `frame/snapshot_registry.py` | takes a snapshot through the registry's public API, metadata only |
| `frame.py` | snapshot to eligible repositories, with the counts |
| `sample.py` | the walking order from the seed, and the development and held-out split |
| `extract.py` | reads tool names and descriptions from TypeScript and Python source |
| `fetch.py` | asks GitHub about one repository, applies the exclusions, unpacks the source at the snapshot commit |
| `survey.py` | the commands above |
| `../../tests/test_mcp_survey.py` | tests for all of it, including the snapshot's hash and counts |

## Known gaps, to settle before the draw

- **A third way to register a tool.** The TypeScript SDK also has `registerToolTask` (experimental). The protocol lists `tool` and `registerTool` only, so the extractor does not read it. On the SDK's own example servers the extractor found all 20 `tool` and `registerTool` calls and none of the 2 `registerToolTask` calls. Adding it is a protocol change.
- **The walk is not written yet.** `fetch` handles one repository. The loop that walks the order, fetches, extracts and stops at 500 kept comes with Phase 1, after the tag.
- **Archived is read on the day of the fetch.** GitHub's API says whether a repository is archived now, not whether it was on the snapshot day. The fetch date is recorded in each row.
- **A renamed repository is followed.** GitHub answers the old name with the new one, and the row records both the listed name and GitHub's current name and numeric id. Two listed names that turn out to be one repository would be counted twice unless the walk checks the id. That rule is not in the protocol yet.
- **Rate limit.** A fetch costs three or four API calls. Without a token GitHub allows 60 calls an hour, so the walk needs `GITHUB_TOKEN` set (5,000 an hour). The token is sent to api.github.com only.
- **Labelling is by hand** and is not automated here.

## Fetching one repository

```bash
python3 survey.py fetch octocat/Hello-World /tmp/hello
```

It prints one row: the commit taken, its date, whether the repository was kept, excluded or unavailable and why, and how many files were unpacked. Nothing from the repository is run. There is no clone and no install, and links, devices and paths that would land outside the folder are left out and counted. The folder must be empty, and it should sit outside this repository: fetched source is not part of the dataset.

For a repository that is in the frame, the command refuses until the protocol is tagged, the same lock as `order`. Any other public repository can be fetched, which is how the tool is tried out.
