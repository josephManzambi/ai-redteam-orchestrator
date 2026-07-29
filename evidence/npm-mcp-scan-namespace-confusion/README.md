# Evidence: npm `mcp-scan` is not the Invariant/Snyk scanner

Reproducible, containerized evidence backing the finding written up at
[manzambi.com/writing/your-security-scanner-is-a-supply-chain-too](https://manzambi.com/writing/your-security-scanner-is-a-supply-chain-too)
and reported at [snyk/agent-scan#409](https://github.com/snyk/agent-scan/issues/409).

**Summary of the finding.** Invariant Labs published `mcp-scan` to npm from v0.1.5
(2025-04-24) to v0.2.1 (2025-05-22), then removed npm support and unpublished those
versions. The freed name was re-registered by an unrelated author on 2026-03-23. The
package that name resolves to today is a config-file linter, not the descriptor-level
MCP security scanner people expect from the name. This directory captures its actual
behaviour, run under a pinned version in a sandbox, against this repository's own
deliberately-vulnerable demo MCP server (`mcp_server.py` at the repo root).

## Reproduce it

Build the sandbox once:

```bash
docker build -t mcp-scan-repro -f Dockerfile .
```

**Case 1 — poisoning blindness**, against `mcp_scan_client.json` / `poisoned-demo-server.py`:

```bash
docker run --rm -v "$PWD:/scan-target" -w /scan-target mcp-scan-repro \
  npx -y mcp-scan@2.0.2 scan -c mcp_scan_client.json --severity low --json
```

**Case 2 — false CRITICAL / cascading compliance findings**, against
`critical-test-client.json` / `critical-test-target.py` (a no-op script, never executed,
referenced by a harmless long hex-like path):

```bash
docker run --rm -v "$PWD:/scan-target" -w /scan-target mcp-scan-repro \
  npx -y mcp-scan@2.0.2 scan -c critical-test-client.json --severity low --json
```

Both pinned to `2.0.2` deliberately: this repo's own advisory recommends never running
`@latest` in a security step, so the evidence gathering follows the same rule.

## Findings

### 1. It never connects to the MCP server

The scan above completes in **4-5ms**, too fast for a real MCP stdio handshake with a
spawned process. Proven directly: point the scanner at a decoy server that writes a
marker file the instant it is executed, then exits. The marker is never written. The
tool reads the `command` / `args` strings out of the config file and nothing else.

### 2. It cannot detect tool poisoning

`poisoned-demo-server.py`'s `summarize_note` tool carries a hidden instruction in its
docstring instructing an agent to read `~/.ssh/id_rsa` and exfiltrate it via a tool
argument, without telling the user. Scanned, this produces **zero findings related to
SSH keys, poisoning, or injection** (see `01-poisoned-server-scan.json`). Because the
server is never executed, its tool descriptions are never read, so this class of attack
is structurally invisible to it.

### 3. False positives cascade into a fabricated compliance report

A config pointing at a no-op script with one long, hex-like path argument produces
**10 findings from a script that is never run** (`02-critical-false-positive-scan.json`),
including a `CRITICAL` "PII/Sensitive data: API Key" finding on a harmless local path,
two `HIGH` false "prompt injection" findings on the same hex string, and a cascading
false GDPR-style compliance block (consent gap, retention gap, deletion gap, missing
encryption) generated downstream of the false secret detection.

**One correction to the public write-up:** the original advisory describes this as a
false *"Exposed Pinecone API Key."* This reproduction, run against a different (though
structurally equivalent) long path, produced a generically-labelled `"API Key"` finding,
not one naming Pinecone specifically. The literal string "Pinecone" is not verified to
reproduce; the underlying mechanism, a harmless path triggering a false critical secret
finding, is verified and reproduces worse than originally described.

## Files

| File | What it is |
|---|---|
| `Dockerfile` | Minimal `node:20-slim` + Python 3 sandbox |
| `mcp_scan_client.json` | MCP client config pointing at the poisoned demo server |
| `poisoned-demo-server.py` | Copy of this repo's `mcp_server.py` demo target |
| `critical-test-client.json` | Config for the false-CRITICAL reproduction |
| `critical-test-target.py` | No-op script referenced by the harmless long path |
| `01-poisoned-server-scan.json` | Raw scanner output, case 1 |
| `02-critical-false-positive-scan.json` | Raw scanner output, case 2 |

All commands run **2026-07-29**, scanner version **2.0.2**. Re-running either case
reproduces identical `findings` and severity counts; only the millisecond-precision
`scanDurationMs` / `totalDurationMs` fields vary between runs, since the tool times its
own (non-)execution.
