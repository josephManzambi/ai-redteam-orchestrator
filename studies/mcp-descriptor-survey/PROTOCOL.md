# MCP descriptor survey: study protocol

**Status: pre-registration draft. Nothing has been collected.** This file is committed before any data is gathered, so the questions, the sample, the rules and the analysis are fixed first and anything that changes later is visible in git history. Open decisions are listed at the end and must be settled before Phase 1 starts.

## Why this study

The orchestrator's descriptor scanner (`mcp_descriptor_scan.py`, `analyze_tool_descriptors`) and the lab's approvals tool flag tool descriptions that look like attacks on the model: instructions aimed at the assistant, references to secret files, parameters that take a command. Today the evidence for how well they work is a handful of constructed examples. Two questions are open, and neither needs a confirmed attack to answer:

1. **How common are these patterns in public MCP servers, and how many of the flags are false alarms?** Claims that "MCP tool poisoning is rampant" and "scanners catch it" both rest on rates nobody has measured on a random sample.
2. **How often does a published server's tool description change without its version changing?** That is the precondition of a rug pull, and it is measurable from public data alone.

## Hypotheses (stated before looking)

- **H1.** Among descriptors flagged by the current keyword rules, at most half are, on human review, instructions aimed at the model that do something other than document the tool. (Expectation: most flags are benign phrasing such as "before using this tool, call list_projects".)
- **H2.** In a random sample of 500 servers with static tool definitions, no descriptor is a confirmed hostile instruction. (Expectation: zero. A zero is a result and will be published as one, with its confidence interval.)
- **H3.** The rules miss most hostile descriptors that use none of their phrases (recall on constructed positives below 60%).
- **H4.** In a re-extraction 30 days later, at least 1 in 50 servers shows a changed tool description with no version change.

H1 to H3 are tested on the held-out half; H4 is a separate longitudinal measurement.

## Design

### Sampling frame
Servers listed in the official MCP Registry (`registry.modelcontextprotocol.io`) at a fixed snapshot date, which have a public GitHub repository. Inclusion: an npm or PyPI package or a repository with at least one statically extractable tool definition (see Extraction). Exclusion: archived repositories, forks that only mirror another listed server, and the author's own projects. The snapshot of the registry listing is committed (names, versions, repository URLs, a SHA-256 of the file), so the frame can be reconstructed.

### Sample and split
Up to 500 servers drawn uniformly at random from the frame with a published seed, stratified by language (TypeScript or Python). The sample is split 50/50 with the same seed into a **development set** (used to read, label and, if needed, adjust rules) and a **held-out set** (touched only once, after the rules are frozen). If the frame has fewer than 500 eligible servers, all of them are used.

### Extraction: static first, no third-party code is run
Descriptors are read from source with a small parser at the repository commit current at the snapshot (the commit SHA is recorded per server):
- TypeScript SDK: `server.tool(name, description, ...)` and `registerTool`.
- Python: `@mcp.tool()` (FastMCP) docstrings and explicit `Tool(name=..., description=...)`.
- Anything built dynamically is recorded as `not statically extractable` and excluded from rates, with the exclusion count reported.

Running servers to call `tools/list` would catch dynamic descriptions but means executing unknown code. That is **out of scope for this protocol** unless the author approves a specific sandbox (a throwaway VM, no network, no credentials, install scripts disabled) and records it as a deviation. Servers needing credentials or services are not run in any case.

### Rules under test
The descriptor rules in `analyze_tool_descriptors` and the Sigma-style keyword rule from the lab's fix pack, **frozen at a recorded commit before the held-out set is opened**. Changes after reading the held-out data are not allowed to change the headline numbers; they may be reported as exploratory.

### Labelling
Each flagged descriptor is labelled by hand into: (a) instruction aimed at the model that goes beyond documenting the tool; (b) reference to a sensitive path or credential; (c) parameter that accepts a command or code; (d) benign, flag is a false alarm. In addition, a random 10% of unflagged descriptors are labelled the same way to estimate what the rules miss. Labelling happens before the rule output is shown, and a second labeller labels a random 20% for agreement (Cohen's kappa). The second labeller must be a person other than the first; if none is available, the agreement figure is reported as absent, not replaced.

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
One command regenerates the frame, sample, extraction and tables from the committed registry snapshot (`make survey`, to be written in Phase 1). Recorded: registry snapshot hash, seed, per-server commit SHAs, parser and rule commits, tool versions. Raw descriptor text is **not** redistributed (it belongs to the servers' authors): the published dataset holds server identifiers, commit SHAs, the label, the rules that fired and a hash of each descriptor; the script re-fetches the text.

## Ethics and disclosure
- Public data only, through the registry API and GitHub's API, within their rate limits, with a generic client name.
- If a descriptor appears to be genuinely hostile or a server appears vulnerable: stop analysing that server, verify without exploiting it, and report privately to the maintainers (the repository's security policy or GitHub private vulnerability reporting) with a 90-day window before any detail is public. Counts are reported without names until a fix exists or the window ends.
- Benign servers are not named in the results; they appear as identifiers in the dataset only.

## Phases
0. This protocol, committed and tagged. 1. Registry snapshot, frame and sample. 2. Static extraction and the exclusion count. 3. Development-set labelling, rule freeze. 4. Held-out evaluation, once. 5. Disclosures, write-up on the evidence page, dataset. 6. The 30-day re-extraction.

## Threats to validity
Static extraction misses dynamic descriptions and favours simple servers. The registry over-represents maintained projects, so rates are not rates for the whole ecosystem. A descriptor is not behaviour: a clean description can sit on a hostile handler. One labeller (or none for agreement) limits label quality. The constructed positives are the author's, so recall on them flatters the rules. These limits go in the write-up's first page.

## Decisions needed before Phase 1
1. Sample size and whether to include servers outside the registry.
2. Whether a sandbox for running `tools/list` is approved, and what it is (default: no).
3. A second labeller, by name.
4. The disclosure contact and where the dataset is published.
5. Who reviews this protocol before it is tagged.
