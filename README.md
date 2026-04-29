# 🛡️ AI Red Team Orchestrator

A single-file, three-layer automated red-team pipeline for auditing LLMs and MCP tool servers. Runs entirely locally against [Ollama](https://ollama.com), using [`uv`](https://docs.astral.sh/uv/) for zero-config dependency management.

The orchestrator ships a **deliberately vulnerable MCP server** as the default system-under-test, then throws four industry-standard attack frameworks at it:

| Layer | Purpose | Tools |
|---|---|---|
| **Layer 1** — Broad Scan | Wide-net vulnerability discovery | [Garak](https://github.com/NVIDIA/garak) + [Promptfoo](https://github.com/promptfoo/promptfoo) eval |
| **Layer 2** — Targeted | OWASP LLM Top-10 taxonomy + MCP attack surface | [Promptfoo](https://github.com/promptfoo/promptfoo) redteam + [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) |
| **Layer 3** — Adversarial | Multi-turn jailbreak + tree search | [PyRIT](https://github.com/Azure/PyRIT) Crescendo + TAP |

Output is a Markdown report (and optionally a self-contained HTML report) with severity badges, an executive summary table, raw tool output in collapsible sections, and actionable recommendations.

## Why?

Most red-team workflows require stitching together 3–4 tools manually, each with their own config format, Python version, and install dance. This script:

- **One file, zero setup** — `uv run` handles all dependencies automatically
- **Runs fully local** — Ollama target, no API keys needed
- **Ships its own vulnerable target** — a deliberately insecure MCP server with path traversal and command injection, so you have something real to find
- **Audit your own MCP servers** — pass `--mcp-config` to point Layer 2's mcp-scan at your real infrastructure
- **Covers breadth and depth** — broad scanning (Garak), targeted taxonomies (OWASP), and adversarial multi-turn attacks (PyRIT) in one run
- **Produces auditable reports** — Markdown and HTML with severity classifications, not just raw logs
- **CI-ready** — exits with code 1 on CRITICAL/HIGH findings (all findings still appear in the report)

## Prerequisites

| Tool | Install | Purpose |
|---|---|---|
| [uv](https://docs.astral.sh/uv/) | `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh \| sh` | Python dependency management |
| [Ollama](https://ollama.com) | `brew install ollama` or [download](https://ollama.com/download) | Local LLM serving |
| [Node.js](https://nodejs.org/) | `brew install node` | Provides `npx` for Promptfoo and mcp-scan |

```bash
# Start the Ollama daemon
ollama serve

# Pull the target model (~4.7 GB)
ollama pull qwen2.5:7b
```

## Quick Start

```bash
# Full three-layer audit with default model
uv run redteam_orchestrator.py

# Target a different model
uv run redteam_orchestrator.py --target mistral:7b

# Run specific layers only
uv run redteam_orchestrator.py --layers 1       # broad scan only
uv run redteam_orchestrator.py --layers 2,3     # targeted + adversarial

# Increase timeout for slow machines (default: 1800s = 30 min)
uv run redteam_orchestrator.py --timeout 7200

# Audit your own MCP server (Layer 2 mcp-scan)
uv run redteam_orchestrator.py --mcp-config path/to/your_mcp_client.json

# Generate both Markdown and HTML reports
uv run redteam_orchestrator.py --html
```

First run takes longer — `uv` builds an ephemeral venv from the script header, and `npx` fetches Promptfoo/mcp-scan. Subsequent runs are faster.

## CLI Reference

```
usage: redteam_orchestrator.py [-h] [--target TARGET] [--provider PROVIDER]
                               [--timeout TIMEOUT] [--mcp-config MCP_CONFIG]
                               [--html] [--layers LAYERS] [--clean]
                               [--clean-deep] [--clean-all] [--yes]

options:
  --target TARGET       Ollama model to audit (default: qwen2.5:7b)
  --provider PROVIDER   LLM provider prefix for Promptfoo (default: ollama)
  --timeout TIMEOUT     Per-step timeout in seconds (default: 1800)
  --mcp-config CONFIG   Path to your own mcp-scan client config JSON (Layer 2)
  --html                Also generate a self-contained HTML report
  --layers LAYERS       Comma-separated layer subset, e.g. '1,3' (default: 1,2,3)
  --clean               Remove generated files only (fast, safe)
  --clean-deep          Files + uv cache + npm cache + ~/.pyrit state
  --clean-all           Deep clean + remove the Ollama target model
  --yes, -y             Skip confirmation prompt for --clean-all
```

## What It Does

### The Vulnerable Target

The orchestrator writes `mcp_server.py` — a FastMCP server with two intentionally vulnerable tools:

- **`read_log(path)`** — Path traversal: concatenates user input into `cat /var/log/{path}` with `shell=True`, no validation. Attackable with `../../etc/passwd`.
- **`system_diagnostics(cmd_suffix)`** — Command injection: appends user input to a shell command with no sanitization. Attackable with `; whoami`, `; cat /etc/shadow`, etc.

This is the default system-under-test. Use `--mcp-config` to point Layer 2's mcp-scan at your own MCP server instead.

### Layer 1 — Broad Scan

Casts a wide net to find obvious vulnerabilities.

- **Garak** runs prompt injection, encoding tricks, malware generation, XSS, leak replay, social engineering (grandma, DAN, glitch, Goodside) probes against the target model.
- **Promptfoo eval** runs four hand-crafted test cases: command injection via `whoami`, path traversal via `../../etc/passwd`, system prompt extraction, and chained translation + injection.

### Layer 2 — Targeted

Tests against known vulnerability taxonomies and audits the MCP tool surface.

- **Promptfoo redteam** generates adversarial test cases using the OWASP LLM Top-10 plugin bundle plus harmful content, PII, hallucination, excessive agency, hijacking, prompt extraction, RBAC, shell injection, and SQL injection plugins. Strategies include jailbreak, composite jailbreak, prompt injection, multilingual, base64, and leetspeak.
- **mcp-scan** statically audits the MCP server's tool descriptors for prompt injection vectors, tool poisoning, and unsafe patterns. Use `--mcp-config` to point this at your own MCP server.

### Layer 3 — Adversarial

Simulates a persistent attacker using multi-turn strategies.

- **PyRIT Crescendo** gradually escalates across 8 turns with 3 backtracks, trying to coerce the model into calling `system_diagnostics` with `; cat /etc/passwd` and `read_log` with `../../etc/shadow`.
- **PyRIT TAP** (Tree of Attacks with Pruning) runs a branching search (width=3, depth=4, branching=2) to find jailbreak paths that bypass safety refusals.

### Reports

**Markdown** (`RedTeam_Report.md`) — always generated. Contains metadata, executive summary table, per-step severity badges (🟥 CRITICAL → 🟩 INFO), notes, raw output in collapsible `<details>` blocks, and recommendations.

**HTML** (`RedTeam_Report.html`) — generated with `--html`. Self-contained dark-themed page with the same content, color-coded badges, collapsible raw output, and no external dependencies. Good for sharing with stakeholders who won't open a `.md` file.

### Exit Codes

The orchestrator **always runs all selected layers to completion** and writes the full report. It never stops early on a finding. The exit code is purely a signal for CI pipelines:

| Code | Meaning |
|---|---|
| `0` | All steps INFO, WARN, or MEDIUM — no critical issues |
| `1` | At least one step classified HIGH or CRITICAL — review the report |

```yaml
# GitHub Actions example
- name: AI Red Team Audit
  run: uv run redteam_orchestrator.py --target ${{ matrix.model }} --timeout 3600
  # Step fails on HIGH/CRITICAL — full report is always available as artifact
```

## Auditing Your Own MCP Server

The `--mcp-config` flag points Layer 2's **mcp-scan** at your own MCP server. Create a client config JSON in the [Claude Desktop / Cursor format](https://modelcontextprotocol.io/docs/tools/inspector):

```json
{
  "mcpServers": {
    "my-server": {
      "command": "python",
      "args": ["path/to/your_mcp_server.py"]
    }
  }
}
```

Then run:

```bash
uv run redteam_orchestrator.py --mcp-config my_mcp_client.json --layers 2
```

**Scope:** `--mcp-config` currently applies to Layer 2 only (mcp-scan). Layers 1 and 3 test the LLM's general safety posture — prompt injection resistance, jailbreak resilience — independent of which MCP server is in play. To customize Layer 3's attack objectives for your specific tool surface, edit the `_pyrit_crescendo_script()` and `_pyrit_tap_script()` functions in the orchestrator, or use standalone PyRIT scripts.

## Cleanup

Three tiers, each strictly larger than the last:

```bash
# Generated files only (fast, safe, repeatable)
uv run redteam_orchestrator.py --clean

# + uv cache, npm cache, ~/.pyrit state
uv run redteam_orchestrator.py --clean-deep

# + Ollama model weights (~4.7 GB, will re-download on next run)
uv run redteam_orchestrator.py --clean-all

# Skip confirmation prompt (for CI/scripts)
uv run redteam_orchestrator.py --clean-all -y
```

### What Gets Removed

| Tier | Files |
|---|---|
| `--clean` | `mcp_server.py`, `promptfoo_*.json`, `mcp_scan_client.json`, `attack_pyrit_*.py`, `RedTeam_Report.md`, `RedTeam_Report.html`, `garak.log`, `garak_report*`, `.promptfoo*`, `redteam-output*` |
| `--clean-deep` | Above + `uv cache clean` + `npm cache clean --force` + `~/.pyrit/` |
| `--clean-all` | Above + `ollama rm <target model>` |

The orchestrator script itself (`redteam_orchestrator.py`) is never removed.

## Troubleshooting

### Ollama not responding

```bash
curl -s http://localhost:11434/api/tags | head  # is daemon running?
ollama ps                                        # is model loaded?
pkill ollama && ollama serve                     # restart if needed
```

### Steps timing out

Either bump the ceiling:
```bash
uv run redteam_orchestrator.py --timeout 7200
```

Or reduce workload by editing the script — set `numTests` to 2 in `_promptfoo_owasp_config()`, trim strategies, reduce Crescendo `max_turns` or TAP `depth`.

For unlimited time on heavy steps, run them standalone:
```bash
uv run python attack_pyrit_tap.py | tee tap_results.txt
```

### PyRIT import errors

PyRIT renames classes between versions. Check what's available:
```bash
uv run python -c "from pyrit import orchestrator; print([x for x in dir(orchestrator) if 'Orchestrator' in x])"
```

### Promptfoo asks for OpenAI key

The config already sets `redteam.provider` and `defaultTest.options.provider` to keep everything on Ollama. If you still see OpenAI errors, ensure no `OPENAI_API_KEY` env var is set.

### `ollama ps` shows nothing during a run

Likely Promptfoo's generation phase is trying to reach OpenAI instead of Ollama. See above. Or the Ollama daemon died — check with `curl http://localhost:11434/api/tags`.

## Project Structure

```
.
├── redteam_orchestrator.py     # the orchestrator (you keep this)
├── LICENSE
├── .gitignore
└── README.md

# Generated at runtime (cleaned by --clean):
├── mcp_server.py               # deliberately vulnerable MCP server
├── promptfoo_broad.json        # Layer 1 Promptfoo config
├── promptfoo_owasp.json        # Layer 2 Promptfoo config
├── mcp_scan_client.json        # Layer 2 mcp-scan target descriptor
├── attack_pyrit_crescendo.py   # Layer 3 Crescendo script
├── attack_pyrit_tap.py         # Layer 3 TAP script
├── RedTeam_Report.md           # Markdown report
├── RedTeam_Report.html         # HTML report (with --html)
├── garak_report_l1.*           # Garak output
└── redteam-output-*.json       # Promptfoo output
```

## Disclaimer

This tool is for **authorized security testing only**. The deliberately vulnerable MCP server (`mcp_server.py`) contains real command injection and path traversal vulnerabilities — do not expose it to untrusted networks or users. Always obtain proper authorization before red-teaming any system you do not own.

## License

[MIT](LICENSE)
