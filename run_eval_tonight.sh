#!/usr/bin/env bash
# run_eval_tonight.sh — overnight adjudicator evaluation (throwaway; not the feature).
# Kicks off: pull judges -> audit qwen2.5:3b -> adjudicator eval -> (optional) regression audit.
# Safe to run unattended; logs everything to eval_night.log. Ctrl-C resumes nothing — just rerun.
set -uo pipefail
cd "$(dirname "$0")"
LOG=eval_night.log
ts() { date '+%H:%M:%S'; }
say() { echo "[$(ts)] $*" | tee -a "$LOG"; }

exec > >(tee -a "$LOG") 2>&1
say "=== adjudicator night run starting ==="

# keep the target + judges resident together (128 GB has room); long keep-alive
export OLLAMA_MAX_LOADED_MODELS=5   # keep all judges + target resident (128 GB fits 70b+8b+7b+7b+3b)
export OLLAMA_KEEP_ALIVE=4h

# 0) preconditions
if ! curl -s "${OLLAMA_HOST:-http://localhost:11434}/api/tags" >/dev/null; then
  say "!! Ollama not reachable. Start it (ollama serve) and rerun."; exit 1
fi

# 1) pull models (target, judges, + regression model)
say "[1/4] pulling models (target, 3 judges, regression model)…"
for m in qwen2.5:3b llama3.1:8b mistral:7b qwen2.5:7b llama3.3:70b llama3.2:3b; do
  say "    ollama pull $m"; ollama pull "$m" || say "    !! pull failed: $m (eval will skip it)"
done

# 2) audit the default target (qwen2.5:3b) — produces RedTeam_Report.md with Layer-3 findings.
#    Exit 1 on HIGH/CRITICAL is EXPECTED (means findings exist); don't abort on it.
say "[2/4] auditing qwen2.5:3b (demo vulnerable server, all layers, ~30-45 min)…"
uv run redteam_orchestrator.py --demo-vulnerable-server --html || say "    audit exited nonzero (findings present) — continuing"
cp -f RedTeam_Report.md report_qwen.md 2>/dev/null && say "    saved report_qwen.md"

# 3) the decisive step: adjudicate anchors + live findings with the candidate judges
say "[3/4] running adjudicator eval (8 anchors + live findings × 3 judges × 5 runs)…"
python3 eval_adjudicator.py --report report_qwen.md \
  --judges llama3.1:8b mistral:7b qwen2.5:7b llama3.3:70b \
  || say "    !! eval errored — check $LOG"
say "    -> adjudicator_eval_report.md  (+ adjudicator_eval_results.csv)"

# 4) OPTIONAL regression: reproduce the article's second-model run (llama3.2:3b).
#    Cheap insurance that the documented nightly numbers still hold on current main.
say "[4/4] regression audit: llama3.2:3b (optional; reproduces article numbers)…"
uv run redteam_orchestrator.py --demo-vulnerable-server --target llama3.2:3b --html || say "    llama audit exited nonzero — continuing"
cp -f RedTeam_Report.md report_llama.md 2>/dev/null && say "    saved report_llama.md"

say "=== done. Review in the morning: adjudicator_eval_report.md ==="
