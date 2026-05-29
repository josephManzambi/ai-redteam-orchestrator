# 🛡️ AI Red Team Orchestrator

A single-file, three-layer automated red-team pipeline for auditing LLMs and MCP tool servers. Its three-layer structure follows the Garak → Promptfoo → PyRIT layering described by [Amine Raji](https://aminrj.com/posts/attack-patterns-red-teaming/); the layer concept and tool mapping are his, while the orchestration, severity classification, reporting, timeout/exit-code/CI design, probe and preset selection are this project's own. Runs entirely locally against [Ollama](https://ollama.com), using [`uv`](https://docs.astral.sh/uv/) for zero-config dependency management.

Point it at your own MCP server and the orchestrator throws four industry-standard attack frameworks at it:

| Layer | Purpose | Tools |
|---|---|---|
| **Layer 1** — Broad Scan | Wide-net vulnerability discovery | [Garak](https://github.com/NVIDIA/garak) + [Promptfoo](https://github.com/promptfoo/promptfoo) eval |
| **Layer 2** — Targeted | OWASP LLM Top-10 taxonomy + MCP attack surface | [Promptfoo](https://github.com/promptfoo/promptfoo) redteam + [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) |
| **Layer 3** — Adversarial | Multi-turn jailbreak + tree search | [PyRIT](https://github.com/Azure/PyRIT) Crescendo + TAP |

Output is a Markdown report (and optionally a self-contained HTML report) with severity badges, an executive summary table, raw tool output in collapsible sections, and recommendations derived from what the run actually found.

## Why?

Most red-team workflows require stitching together 3–4 tools manually, each with their own config format, Python version, and install dance. This script:

- **One file, zero setup** — `uv run` handles all dependencies automatically
- **Runs fully local** — Ollama target, no API keys needed
- **Brings your own MCP server** — point Layer 2's mcp-scan at your real server with `--mcp-config`
- **Optional vulnerable demo target** — opt in with `--demo-vulnerable-server` if you want something to find out of the box (off by default)
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

# Pull the target model (~1.9 GB)
ollama pull qwen2.5:3b
```

## Quick Start

The default flow audits the LLM's general safety posture (Layers 1 + 3) and runs mcp-scan against **your** MCP server:

```bash
# Audit your own MCP server (recommended)
uv run redteam_orchestrator.py --mcp-config path/to/your_mcp_client.json --html

# Same, with a different model
uv run redteam_orchestrator.py --mcp-config my.json --target mistral:7b --html

# Run specific layers only
uv run redteam_orchestrator.py --mcp-config my.json --layers 1       # broad scan only
uv run redteam_orchestrator.py --mcp-config my.json --layers 2,3     # targeted + adversarial

# Increase timeout for slow machines (default: 3600s = 60 min)
uv run redteam_orchestrator.py --mcp-config my.json --timeout 7200
```

If you don't pass `--mcp-config`, the orchestrator still runs Layers 1 and 3 against the LLM — it just **skips mcp-scan** with a clear note in the report.

First run takes longer — `uv` builds an ephemeral venv from the script header, and `npx` fetches Promptfoo/mcp-scan. Subsequent runs are faster.

## Trying It Without Your Own MCP Server

If you want to see the whole pipeline including Layer 2 mcp-scan but don't have an MCP server to point at, opt in to the built-in demo target:

```bash
uv run redteam_orchestrator.py --demo-vulnerable-server --html
```

> ⚠️ **Warning:** the demo server (`mcp_server.py`, written to the working directory only when this flag is set) contains **real command injection and path traversal vulnerabilities** by design. Do not run it on a shared host, do not expose it to untrusted networks, and remove it with `--clean` when you're done. `--mcp-config` and `--demo-vulnerable-server` are mutually exclusive.

## CLI Reference

```
usage: redteam_orchestrator.py [-h] [--target TARGET] [--provider PROVIDER]
                               [--timeout TIMEOUT] [--mcp-config MCP_CONFIG]
                               [--demo-vulnerable-server] [--html]
                               [--no-versions] [--layers LAYERS] [--clean]
                               [--clean-deep] [--clean-all] [--yes]

options:
  --target TARGET            Ollama model to audit (default: qwen2.5:3b)
  --provider PROVIDER        LLM provider prefix for Promptfoo (default: ollama)
  --timeout TIMEOUT          Per-step timeout in seconds (default: 3600)
  --mcp-config CONFIG        Path to your own mcp-scan client config JSON (Layer 2)
  --demo-vulnerable-server   Install + target the built-in vulnerable demo (off by default)
  --html                     Also generate a self-contained HTML report
  --no-versions              Skip the tool-version probe in the report header
  --layers LAYERS            Comma-separated layer subset, e.g. '1,3' (default: 1,2,3)
  --clean                    Remove generated files only (fast, safe)
  --clean-deep               Files + uv cache + npm cache + ~/.pyrit state
  --clean-all                Deep clean + remove the Ollama target model
  --yes, -y                  Skip confirmation prompt for --clean-all
```

## What It Does

### Layer 1 — Broad Scan

Casts a wide net to find obvious vulnerabilities in the LLM. Independent of which MCP server (if any) is in play.

- **Garak** runs `latentinjection`, `dan`, and `goodside` probes against
  the target model. The probe list is intentionally focused — the wider
  set the orchestrator originally shipped (xss, glitch, malwaregen,
  leakreplay) was renamed or removed in Garak 0.14, and the heaviest
  remaining family, `promptinject`, is omitted from the default because
  it consistently times out on a laptop-grade Ollama target. Garak still
  runs under its own larger timeout budget (see "Per-step timeouts"
  below). To run the full sweep, re-add `promptinject` to the `probes`
  variable in `layer1_broad_scan()` and bump the budget further.
- **Promptfoo eval** runs four hand-crafted test cases: command injection via `whoami`, path traversal via `../../etc/passwd`, system prompt extraction, and chained translation + injection. The local Ollama model is wired in as the `llm-rubric` grader so no `OPENAI_API_KEY` is required.

### Layer 2 — Targeted

Tests against known vulnerability taxonomies and audits the MCP tool surface.

- **Promptfoo redteam** generates adversarial test cases against the OWASP
  LLM Top-10 plugin bundle plus excessive-agency, prompt-extraction, and
  shell-injection plugins. Strategies are jailbreak and prompt-injection.
  Scope is intentionally trimmed to keep the preset tractable on a
  laptop-grade Ollama target — `numTests=1` × 4 plugins × 2 strategies — but
  the redteam preset still does not always fit inside the default per-step
  timeout on a 7B model, which is why Layer 2 has its own larger timeout
  budget (see "Per-step timeouts" below). For a wider audit, edit
  `_promptfoo_owasp_config()` and pass `--timeout 14400` or higher. The
  trim is pinned by `tests/test_generated_artifacts.py` so it cannot
  silently re-bloat.
- **mcp-scan** statically audits an MCP server's tool descriptors for prompt injection vectors, tool poisoning, and unsafe patterns. Runs against `--mcp-config` if you provide one, the built-in demo if `--demo-vulnerable-server` is set, otherwise **skipped** with a clear note in the report.

### Layer 3 — Adversarial

Simulates a persistent attacker using multi-turn strategies. Tests the LLM's refusal behavior; doesn't depend on which MCP server is in play.

- **PyRIT Crescendo** gradually escalates across 8 turns with 3 backtracks, trying to coerce the model into shell-shaped tool calls.
- **PyRIT TAP** (Tree of Attacks with Pruning) runs a branching search
  (width=2, depth=2, branching=2, on-topic checking off) to find jailbreak
  paths that bypass safety refusals. Tree shape is tuned to ~24 model calls
  so it fits in a few minutes on a laptop 7B; bump the dimensions in
  `_pyrit_tap_script()` for a deeper search.

The PyRIT scripts pin PyRIT to 0.8.1 (0.9 moved orchestrators out of
`pyrit.orchestrator`) and include a fallback for `initialize_pyrit` across
the 0.x renames. Because PyRIT 0.8 dropped `OllamaChatTarget`, the generated
scripts talk to Ollama through its OpenAI-compatible endpoint at
`http://localhost:11434/v1` via `OpenAIChatTarget`. Both behaviors are
pinned by `tests/test_generated_artifacts.py`.

### Per-step timeouts

Not every step is equally expensive. mcp-scan and Promptfoo's broad eval
finish in seconds; Garak's `promptinject` family and Promptfoo's redteam
preset can take an hour or more on a laptop 7B. To stop the slow steps
from getting killed at the global ceiling while the fast steps don't need
the headroom, the orchestrator uses per-layer timeout overrides:

| Step                          | Timeout (seconds) |
|-------------------------------|-------------------|
| Garak full vulnerability sweep| 14400 (4h)        |
| Promptfoo broad evaluation    | 3600 (uses `--timeout`) |
| Promptfoo OWASP redteam preset| 7200 (2h)         |
| mcp-scan static audit         | 3600 (uses `--timeout`) |
| PyRIT Crescendo               | 3600 (uses `--timeout`) |
| PyRIT Tree of Attacks         | 3600 (uses `--timeout`) |

`--timeout N` raises the global ceiling for steps that don't have a
per-layer override, and also raises the per-layer overrides if `N` is
larger than the default for that step. So `--timeout 21600` will give
Garak 6h and Promptfoo OWASP 6h. Lowering `--timeout` below the
per-layer default does not lower the per-layer override — slow steps
always get at least their default.

### Reports

**Markdown** (`RedTeam_Report.md`) — always generated. Contains metadata, executive summary table with status + severity columns, per-step badges (🟥 CRITICAL → 🟩 INFO → ⚪ NOT RUN), notes, raw output (ANSI-stripped) in collapsible `<details>` blocks, and recommendations derived from actual findings.

**HTML** (`RedTeam_Report.html`) — generated with `--html`. Self-contained, light/dark adaptive page with the same content, accessible badges (icon + text), anchor links from the summary table to each step, per-step duration, a top-of-page banner if any step did not complete, and a print stylesheet.

The report distinguishes step **status** (`completed` / `errored` / `timed out` / `skipped`) from **severity** — failed and skipped steps will never be shown as "INFO clean".

### Exit Codes

The orchestrator **always runs all selected layers to completion** and writes the full report. It never stops early on a finding. The exit code is purely a signal for CI pipelines:

| Code | Meaning |
|---|---|
| `0` | All steps INFO, WARN, or MEDIUM — no critical issues |
| `1` | At least one step classified HIGH or CRITICAL — review the report |

```yaml
# GitHub Actions example
- name: AI Red Team Audit
  run: uv run redteam_orchestrator.py --mcp-config ci/mcp.json --target ${{ matrix.model }} --timeout 3600
  # Step fails on HIGH/CRITICAL — full report is always available as artifact
```

## OWASP Coverage Mapping

How this tool's layers map onto two OWASP taxonomies. Coverage is deliberately conservative — a light, single-agent / single-server red-team tool, not an exhaustive audit.

Levels: 🟢 Direct · 🟡 Partial · 🔵 Indirect · ⬜ Not covered

### OWASP MCP Top 10

| ID | Risk | Coverage | Provided by |
|---|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | 🔵 Indirect | mcp-scan flags high-entropy strings in tool arguments _(static heuristic only; no token lifecycle/rotation testing)_ |
| MCP02 | Excessive Permissions & Privilege Escalation | 🟡 Partial | mcp-scan flags risky capability combos (e.g. filesystem + network = exfiltration vector) _(static; no runtime privilege-escalation testing)_ |
| MCP03 | Tool Poisoning | 🟡 Partial | mcp-scan static audit of tool descriptors for injection/poisoning patterns _(descriptor-level only; no behavioural detection)_ |
| MCP04 | Software Supply Chain & Dependency Tampering | ⬜ Not covered | _Garak packagehallucination is model-layer, not MCP dependency tampering_ |
| MCP05 | Command Injection | 🟢 Direct | Promptfoo eval (whoami, '; id'), Garak exploitation, PyRIT objectives coercing system_diagnostics '; cat /etc/passwd' |
| MCP06 | Context Over-sharing | ⬜ Not covered | — |
| MCP07 | Insufficient Authentication & Authorization | ⬜ Not covered | _operator/deployment control; not exercised_ |
| MCP08 | Audit & Logging Gaps | ⬜ Not covered | — |
| MCP09 | Shadow MCP Servers | ⬜ Not covered | _requires registry/discovery testing_ |
| MCP10 | Model Misbinding & Context Spoofing | 🟡 Partial | Garak latentinjection (single-hop indirect/context injection) _(no model-binding or covert-channel testing)_ |

### OWASP LLM Top 10 (2025)

| ID | Risk | Coverage | Provided by |
|---|---|---|---|
| LLM01 | Prompt Injection | 🟢 Direct | Garak goodside + latentinjection, Promptfoo 'ignore previous instructions' case, Promptfoo OWASP prompt-injection strategy |
| LLM02 | Sensitive Information Disclosure | 🟡 Partial | Promptfoo path traversal ('/etc/passwd') + system-prompt extraction; PyRIT exfiltration objectives |
| LLM03 | Supply Chain | ⬜ Not covered | _Garak packagehallucination is adjacent (model-layer), not LLM supply-chain_ |
| LLM04 | Data and Model Poisoning | ⬜ Not covered | — |
| LLM05 | Improper Output Handling | 🟡 Partial | Garak ansiescape + web_injection.MarkdownImageExfil / MarkdownXSS (unsafe/structured output) |
| LLM06 | Excessive Agency | 🟡 Partial | PyRIT tool-coercion; Promptfoo OWASP excessive-agency plugin _(OWASP plugin skipped unless 'promptfoo auth login')_ |
| LLM07 | System Prompt Leakage | 🟢 Direct | Promptfoo system-prompt extraction case; Promptfoo OWASP prompt-extraction plugin |
| LLM08 | Vector and Embedding Weaknesses | ⬜ Not covered | — |
| LLM09 | Misinformation | 🔵 Indirect | Garak packagehallucination (hallucinated package names) _(narrow slice of the misinformation class)_ |
| LLM10 | Unbounded Consumption | ⬜ Not covered | — |

**OWASP Agentic (ASI01–ASI10): intentionally not scored.** This is a single-agent, single-server tool, so the genuinely multi-agent ASI risks — ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI10 Rogue Agents — are structurally out of scope. The single-agent-flavoured ASI risks it does touch (ASI01 Goal Hijack, ASI02 Tool Misuse, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning) are already reflected in the LLM and MCP tables above.

## Auditing Your Own MCP Server

Create a client config JSON in the [Claude Desktop / Cursor format](https://modelcontextprotocol.io/docs/tools/inspector):

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

**Scope:** `--mcp-config` applies to Layer 2 only (mcp-scan). Layers 1 and 3 test the LLM's general safety posture — prompt injection resistance, jailbreak resilience — independent of which MCP server is in play. To customize Layer 3's attack objectives for your specific tool surface, edit the `_pyrit_crescendo_script()` and `_pyrit_tap_script()` functions in the orchestrator, or run standalone PyRIT scripts.

## Cleanup

Three tiers, each strictly larger than the last:

```bash
# Generated files only (fast, safe, repeatable)
uv run redteam_orchestrator.py --clean

# + uv cache, npm cache, ~/.pyrit state
uv run redteam_orchestrator.py --clean-deep

# + Ollama model weights (will re-download on next run)
uv run redteam_orchestrator.py --clean-all

# Skip confirmation prompt (for CI/scripts)
uv run redteam_orchestrator.py --clean-all -y
```

### What Gets Removed

| Tier | Files |
|---|---|
| `--clean` | `mcp_server.py` (if installed), `promptfoo_*.json`, `mcp_scan_client.json`, `attack_pyrit_*.py`, `RedTeam_Report.md`, `RedTeam_Report.html`, `garak.log`, `garak_report*`, `.promptfoo*`, `redteam-output*` |
| `--clean-deep` | Above + `uv cache clean` + `npm cache clean --force` + `~/.pyrit/` |
| `--clean-all` | Above + `ollama rm <target model>` |

The orchestrator script itself (`redteam_orchestrator.py`) is never removed.

## Tests

The orchestrator ships with a pytest suite under `tests/` that pins the
contracts that have actually broken in the wild:

- `test_classify.py` — severity heuristics: `/etc/passwd` leak → CRITICAL,
  jailbreak markers → HIGH, errored/timed-out steps → NOT_RUN (never
  INFO).
- `test_run_step.py` — exit-code handling: promptfoo `rc=100` (assertions
  failed) and mcp-scan `rc!=0` (findings present) are both reclassified
  as `completed`, not `errored`.
- `test_generated_artifacts.py` — generated PyRIT scripts must parse,
  must use `OpenAIChatTarget` (not the dropped `OllamaChatTarget`), and
  the trimmed Promptfoo / TAP / Garak scopes are pinned so they cannot
  silently re-bloat.

```bash
uv run --with pytest --with rich --with "pyrit==0.8.1" pytest tests/ -v
```

CI runs the same command on every push to main and every pull request
(`.github/workflows/test.yml`).

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

The orchestrator's PyRIT scripts already fall back across `pyrit.common.initialize_pyrit` and `pyrit.common.initialization.initialize_pyrit`. If you still hit a class rename, check what's available:
```bash
uv run python -c "from pyrit import orchestrator; print([x for x in dir(orchestrator) if 'Orchestrator' in x])"
```

### Promptfoo asks for OpenAI key

The configs set `redteam.provider` and `defaultTest.options.provider` to keep everything on Ollama (including the `llm-rubric` grader). If you still see OpenAI errors, ensure no `OPENAI_API_KEY` env var is set.

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
├── promptfoo_broad.json        # Layer 1 Promptfoo config
├── promptfoo_owasp.json        # Layer 2 Promptfoo config
├── attack_pyrit_crescendo.py   # Layer 3 Crescendo script
├── attack_pyrit_tap.py         # Layer 3 TAP script
├── RedTeam_Report.md           # Markdown report
├── RedTeam_Report.html         # HTML report (with --html)
├── garak_report_l1.*           # Garak output
└── redteam-output-*.json       # Promptfoo output

# Generated only with --demo-vulnerable-server:
├── mcp_server.py               # deliberately vulnerable MCP server (opt-in)
└── mcp_scan_client.json        # mcp-scan target descriptor for the demo
```

## Known Limitations

- **The same model is used as target, attacker, and scorer.** In Layer 3 the
  generated PyRIT scripts wire one Ollama model into all three roles —
  `objective_target`, `adversarial_chat`, and `scoring_target` (see
  `_ollama_target()` in `_pyrit_crescendo_script()` and
  `_pyrit_tap_script()`). A small local model is a weak adversary *and* a
  self-biased judge, which materially weakens the adversarial layer: it may
  miss attacks a stronger attacker would find, and may grade its own
  borderline successes as refusals. Treat a "clean" Layer 3 result as
  low-confidence. For a real assessment, point the adversarial and scoring
  targets at a stronger, separate model.
- **Severity classification is heuristic.** `classify()` derives severity
  from word-boundary keyword matches in tool output. It is precise enough to
  avoid the obvious false positives ("0 failures", probe names containing
  "exploit"), but it can still miss novel phrasings — it is not a substitute
  for reading the raw output captured in the report.
- **Scope is trimmed for laptop-grade targets.** The default Garak probe set,
  the Promptfoo OWASP plugin/strategy bundle, and the TAP tree size are all
  reduced so a run completes on a laptop Ollama target. A serious audit should
  widen them (see the per-layer notes above) and raise the timeouts.
- **Layer 4 (manual expert testing) is out of scope** — see Acknowledgments.

## Disclaimer

This tool is for **authorized security testing only**. The optional demo MCP server (installed only via `--demo-vulnerable-server`) contains real command injection and path traversal vulnerabilities — do not expose it to untrusted networks or users. Always obtain proper authorization before red-teaming any system you do not own.

## Acknowledgments

The layered Garak → Promptfoo → PyRIT structure of this orchestrator
follows the red-teaming methodology described by Amine Raji in [LLM Red
Teaming Tools: PyRIT & Garak (2025
Guide)](https://aminrj.com/posts/attack-patterns-red-teaming/), which
maps a four-layer testing strategy across those tools. That layer concept
and tool mapping are his.

Everything else here is this project's own: the single-file orchestration
and layer sequencing, the severity classifier, the Markdown/HTML report
generator, the per-layer timeout overrides, the CI exit-code gating, the
cleanup tiers and CLI, and the specific Garak probes, Promptfoo plugins,
and PyRIT objectives each layer runs (which differ from the article's
examples — e.g. it uses the `owasp:llm` plugin set rather than the OWASP
Agentic preset). Layer 4 (manual expert testing) is intentionally out of
scope, since no orchestrator replaces a human who has read your codebase.

Read his article first if you want the threat-model framework, the
OWASP Agentic Top 10 / MITRE ATLAS / CSA mapping, and the case studies
that motivate why agentic AI testing needs its own methodology.

## License

[MIT](LICENSE)
