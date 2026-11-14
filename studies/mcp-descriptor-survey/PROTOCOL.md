# MCP descriptor survey: study protocol

**Status: pre-registration draft, decisions 1 to 3 settled on 14 November 2026. Nothing has been collected and no sample has been drawn.** This file is committed before any data is gathered, so the questions, the sample, the rules and the analysis are fixed first and anything that changes later is visible in git history. Two decisions are still open (the second labeller and the reviewer, see the end); the protocol is not tagged, and the sample is not drawn, until a reviewer is named.

## Why this study

The orchestrator's descriptor scanner (`mcp_descriptor_scan.py`, `analyze_tool_descriptors`) and the lab's approvals tool flag tool descriptions that look like attacks on the model: instructions aimed at the assistant, references to secret files, parameters that take a command. Today the evidence for how well they work is a handful of constructed examples. Two questions are open, and neither needs a confirmed attack to answer:

1. **How common are these patterns in public MCP servers, and how many of the flags are false alarms?** Claims that "MCP tool poisoning is rampant" and "scanners catch it" both rest on rates nobody has measured on a random sample.
2. **How often does a published server's tool description change without its version changing?** That is the precondition of a rug pull, and it is measurable from public data alone.

## Hypotheses (stated before looking)

- **H1.** Among descriptors flagged by the current keyword rules, at most half are, on human review, instructions aimed at the model that do something other than document the tool. (Expectation: most flags are benign phrasing such as "before using this tool, call list_projects".)
- **H2.** In the sample of 500 repositories with static tool definitions, no descriptor is a confirmed hostile instruction. (Expectation: zero. A zero is a result and will be published as one, with its confidence interval.)
- **H3.** The rules miss most hostile descriptors that use none of their phrases (recall on constructed positives below 60%).
- **H4.** In a re-extraction 30 days later, at least 1 in 50 repositories shows a changed tool description with no version change.

H1 to H3 are tested on the held-out half; H4 is a separate longitudinal measurement.

## Design

### Sampling frame
Servers listed in the official MCP Registry (`registry.modelcontextprotocol.io`) at a fixed snapshot date, which have a public GitHub repository and an npm or PyPI package. The snapshot used is the one recorded in `FRAME-CHECK.md` (SHA-256 `eced3ccbc61f1c99324244b2b8722ab1990757a2b403acab076172bae1c9def2`): 20,289 such entries across 17,232 distinct repositories. The registry only: servers outside it are out of scope. Exclusion: archived repositories, forks that only mirror another listed server, and the author's own projects. The snapshot of the registry listing is committed (names, versions, repository URLs, a SHA-256 of the file), so the frame can be reconstructed.

### Sample and split
**The unit is the repository, not the registry entry**, so one monorepo that lists many servers is counted once. Repositories are put in a random order with a published seed (**20261114**), separately for TypeScript and Python, and the two lists are interleaved in proportion to their size in the frame. Walking that order, each repository is extracted (see below) and kept if it has at least one statically extractable tool definition; the walk stops at **500 repositories kept**, or at the end of the frame. Repositories skipped because nothing could be extracted are counted and reported, by reason. This is written down before any extraction so that "the first 500 that work" cannot be adjusted afterwards.

The 500 are split 50/50 by position in that order (odd and even) into a **development set** (used to read, label and, if needed, adjust rules) and a **held-out set** (touched only once, after the rules are frozen). Where a repository holds several servers, all of its extractable tools are analysed together and the repository is the unit in every rate.

### Extraction: static first, no third-party code is run
Descriptors are read from source with a small parser at the repository commit current at the snapshot (the commit SHA is recorded per server):
- TypeScript SDK: `server.tool(name, description, ...)` and `registerTool`.
- Python: `@mcp.tool()` (FastMCP) docstrings and explicit `Tool(name=..., description=...)`.
- Anything built dynamically is recorded as `not statically extractable` and excluded from rates, with the exclusion count reported.

Running servers to call `tools/list` would catch dynamic descriptions but means executing unknown code. **Decision: no server is run. The survey is static only.** A sandbox would be a recorded deviation approved by the author, with a specific setup (a throwaway VM, no network, no credentials, install scripts disabled); none is approved. Servers needing credentials or services are not run in any case.

### Rules under test
The descriptor rules in `analyze_tool_descriptors` and the Sigma-style keyword rule from the lab's fix pack, **frozen at a recorded commit before the held-out set is opened**. Changes after reading the held-out data are not allowed to change the headline numbers; they may be reported as exploratory.

### Labelling
Each flagged descriptor is labelled by hand into: (a) instruction aimed at the model that goes beyond documenting the tool; (b) reference to a sensitive path or credential; (c) parameter that accepts a command or code; (d) benign, flag is a false alarm. In addition, a random 10% of unflagged descriptors are labelled the same way to estimate what the rules miss. Labelling happens before the rule output is shown, and a second labeller labels a random 20% for agreement (Cohen's kappa). The second labeller must be a person other than the first; if none is named before labelling starts, the agreement figure is reported as absent, not replaced.

### Positive controls
Real, confirmed hostile descriptors are expected to be absent from a random sample, so recall cannot be measured on it. Recall is measured on a **constructed set** clearly labelled synthetic: the lab's own poisoned-tool and rug-pull examples and published proof-of-concept patterns, rewritten with and without the rules' phrases. This estimates recall on known shapes only, and the write-up says so.

### Longitudinal measurement (H4)
Re-run extraction on the same servers 30 days after the snapshot (new SHAs, same parser). Report the share with a changed description, split by whether the package version changed.

## Analysis (fixed in advance)
- Prevalence of each label with 95% Wilson intervals, per set.
- Precision of the rules on flagged descriptors (confirmed (a) to (c) over all flagged), recall on the constructed set, and the estimated miss rate from the unflagged sample.
- Rates are reported over servers with extractable tools; the number excluded is stated.
- No server is scored as "safe". A zero means none was found by these methods in this sample.

## Reproducibility
One command regenerates the frame, sample, extraction and tables from the committed registry snapshot (the 281 MB snapshot itself is not committed; its SHA-256 is, and `frame/snapshot_registry.py` re-creates it) (`make survey`, to be written in Phase 1). Recorded: registry snapshot hash, seed, per-server commit SHAs, parser and rule commits, tool versions. Raw descriptor text is **not** redistributed (it belongs to the servers' authors): the published dataset holds server identifiers, commit SHAs, the label, the rules that fired and a hash of each descriptor; the script re-fetches the text.

## Ethics and disclosure
- **Disclosure contact:** private reports go from the author to the maintainers; maintainers and anyone else reach the author at the address published on manzambi.com (joseph@manzambi.com).
- **Where the dataset lives:** a public folder of this repository (`studies/mcp-descriptor-survey/data/`), committed with the registry snapshot hash. It holds identifiers, commit SHAs, labels, the rules that fired and descriptor hashes, never descriptor text.
- Public data only, through the registry API and GitHub's API, within their rate limits, with a generic client name.
- If a descriptor appears to be genuinely hostile or a server appears vulnerable: stop analysing that server, verify without exploiting it, and report privately to the maintainers (the repository's security policy or GitHub private vulnerability reporting) with a 90-day window before any detail is public. Counts are reported without names until a fix exists or the window ends.
- Benign servers are not named in the results; they appear as identifiers in the dataset only.

## Phases
0. This protocol, committed and tagged. 1. Registry snapshot, frame and sample. 2. Static extraction and the exclusion count. 3. Development-set labelling, rule freeze. 4. Held-out evaluation, once. 5. Disclosures, write-up on the evidence page, dataset. 6. The 30-day re-extraction.

## Threats to validity
Static extraction misses dynamic descriptions and favours simple servers. The registry over-represents maintained projects, so rates are not rates for the whole ecosystem. A descriptor is not behaviour: a clean description can sit on a hostile handler. One labeller (or none for agreement) limits label quality. The constructed positives are the author's, so recall on them flatters the rules. These limits go in the write-up's first page.

## Decisions
1. **Sample size and frame: settled.** 500 repositories from the registry only, drawn over repositories with seed 20261114, stratified by language (see above).
2. **Sandbox: settled.** None. Static extraction only.
3. **Disclosure contact and dataset home: settled.** The contact on manzambi.com; a public folder of this repository (see Ethics).
4. **Second labeller: open.** Named by the author, who asks them first. If none is named before labelling starts, agreement is reported as absent.
5. **Protocol reviewer: open.** Named by the author, who asks them first. The protocol is tagged, and the sample is drawn, only after the reviewer's comments are in the history or the reviewer declines in writing.
