# MCP descriptor survey

A survey of tool descriptions in public MCP servers: how often they contain the patterns scanners flag, how many of those flags are false alarms, and how often a description changes without a version change. The design is fixed in advance in [PROTOCOL.md](PROTOCOL.md).

**Where it stands (27 November 2026).** The protocol is written and amended once. The frame is counted ([FRAME-CHECK-2026-11-27.md](FRAME-CHECK-2026-11-27.md)). The tools below exist and are tested. **No sample has been drawn and no repository has been fetched.** That waits for a reviewer (PROTOCOL.md, decision 5).

## Commands

Python 3.9 or later, standard library only. Nothing here runs third-party code.

```bash
python3 survey.py counts             # the frame's size, from the committed snapshot
python3 survey.py extract <folder>   # tools found in one checked-out repository
python3 survey.py order              # the sample draw: refuses until the protocol is tagged
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
| `survey.py` | the commands above |
| `../../tests/test_mcp_survey.py` | tests for all of it, including the snapshot's hash and counts |

## Known gaps, to settle before the draw

- **A third way to register a tool.** The TypeScript SDK also has `registerToolTask` (experimental). The protocol lists `tool` and `registerTool` only, so the extractor does not read it. On the SDK's own example servers the extractor found all 20 `tool` and `registerTool` calls and none of the 2 `registerToolTask` calls. Adding it is a protocol change.
- **Fetching repositories is not written yet.** The protocol reads each repository at the commit current at the snapshot. That step, and the check for archived repositories and mirror forks, comes with Phase 1.
- **Labelling is by hand** and is not automated here.
