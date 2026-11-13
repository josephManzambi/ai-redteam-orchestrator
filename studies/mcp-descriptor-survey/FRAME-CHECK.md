# MCP descriptor survey: frame check (13 November 2026)

**Status: a count of the sampling frame, not Phase 1.** No sample has been drawn, nothing has been extracted, and the protocol's open decisions are still open. This file records how big the frame is, so those decisions can be made with the number in front of you. It is an addendum: it does not change `PROTOCOL.md`.

## What was done
The official registry's listing was read in full through its public API (`frame/snapshot_registry.py`, a generic client name, a pause between pages): metadata only, no server or package downloaded or run. The listing has **250,627 entries** (every published version of every server). The raw file is 281 MB and is not committed. Its SHA-256, so the exact snapshot can be identified, is:

`eced3ccbc61f1c99324244b2b8722ab1990757a2b403acab076172bae1c9def2`

(The registry changes continuously, so re-running the script later gives a different file. The hash identifies this one. The sample, when drawn, should use a snapshot committed in a compact form.)

## Counts, latest version of each server
| | Servers |
|---|---|
| Distinct servers (latest version each) | 63,406 |
| of which status `active` | 62,406 |
| active, with no repository URL | 22,212 |
| active, with a GitHub repository | 40,101 |
| active, GitHub repository and an npm or PyPI package | **20,289** (npm 15,544; PyPI 4,906) |
| distinct GitHub repositories behind those | **17,232** |
| active, GitHub repository, no package (remote or unspecified) | 17,283 |

## What this means for the protocol
- **A correction to my earlier figure.** A first, partial pass (the first 15,000 entries, which are sorted by name) suggested about 360 servers with a GitHub repository and an npm or PyPI package. The full listing says about 20,000. Do not quote the earlier number.
- **The frame is large, so a random sample of 300 to 500 is a small fraction** (under 3% of the 17,232 repositories). The protocol's "all eligible if fewer than 500" case does not apply.
- **Many entries share a repository** (20,289 servers across 17,232 repositories, and a monorepo can list many servers), so the sample should be drawn over repositories, not servers, to avoid counting one codebase many times. This is a design choice for the author to confirm before Phase 1.
- **The registry holds a lot of low-effort or duplicate entries** (22,212 active entries have no repository at all), so a random sample will include many servers with nothing to extract. The protocol already excludes servers without statically extractable tools and reports the exclusion count; the expected exclusion rate is now known to be large and should be planned for.
- **The sample size should be decided with this in mind** (decision 1 in the protocol): enough servers survive extraction to give usable intervals. Oversampling, then drawing the first 300 to 500 extractable servers in a fixed seeded order, is one way; it must be written into the protocol before the draw.

## Not decided here
The second labeller, the sandbox question, the disclosure contact and the protocol's reviewer remain the author's. Phase 1 (the sample) does not start until they are settled and this addendum is read.
