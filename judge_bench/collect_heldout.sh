#!/usr/bin/env bash
# collect_heldout.sh: fresh Layer 3 transcripts the judge benchmark has never seen.
#
# judge_bench/RESULTS.md was measured on 45 responses from four runs on
# 28-31 October 2026, one target, and rules written against that same set. This
# collects a held-out set: new Crescendo and TAP runs on the same target, plus a
# second target from another family, so the judges (and the rules) can be checked
# on data they were not tuned on.
#
# Usage (Ollama running; takes about 1 to 2 hours; keeps the Mac awake):
#   bash judge_bench/collect_heldout.sh            # 3 runs per target
#   RUNS=2 bash judge_bench/collect_heldout.sh
#
# Output: one evidence/runs/<timestamp>/ folder per run, listed in
# judge_bench/heldout_runs.txt as "<run_id> <target>". The next step (by hand,
# then a script) is extracting each target response into a labelled .jsonl and
# running: uv run judge_bench/bench.py --judges <models> --cases <file>
#
# Exit codes: an audit exits 1 when it finds HIGH/CRITICAL, which is expected
# here and does not stop the loop.
set -uo pipefail
cd "$(dirname "$0")/.."

RUNS="${RUNS:-3}"
# Same target as the original set, then a different family. mistral:7b is the
# second target, so leave it out of the judges when scoring its transcripts.
TARGETS=("qwen2.5:7b-instruct-q8_0" "mistral:7b")
LOG=judge_bench/heldout.log
MANIFEST=judge_bench/heldout_runs.txt
export OLLAMA_MAX_LOADED_MODELS=2 OLLAMA_KEEP_ALIVE=2h

ts() { date '+%H:%M:%S'; }
say() { echo "[$(ts)] $*" | tee -a "$LOG"; }

if ! curl -s "${OLLAMA_HOST:-http://localhost:11434}/api/tags" >/dev/null; then
  say "Ollama is not reachable. Start it (ollama serve) and run this again."; exit 1
fi
for t in "${TARGETS[@]}"; do
  ollama list | awk '{print $1}' | grep -qx "$t" || { say "Missing model $t: run 'ollama pull $t' first."; exit 1; }
done

say "=== held-out collection: ${#TARGETS[@]} targets x $RUNS runs, Layer 3 only ==="
for t in "${TARGETS[@]}"; do
  for i in $(seq 1 "$RUNS"); do
    before=$(ls -1 evidence/runs 2>/dev/null | sort | tail -1)
    say "target $t, run $i of $RUNS"
    caffeinate -i uv run redteam_orchestrator.py --target "$t" --layers 3 --no-versions >>"$LOG" 2>&1 \
      || say "  audit exited non-zero (findings or an error; see the log), continuing"
    after=$(ls -1 evidence/runs 2>/dev/null | sort | tail -1)
    if [ -n "$after" ] && [ "$after" != "$before" ]; then
      echo "$after $t" >> "$MANIFEST"; say "  saved evidence/runs/$after"
    else
      say "  no new evidence folder for this run (check the log)"
    fi
  done
done
say "=== done: $(wc -l < "$MANIFEST" | tr -d ' ') runs listed in $MANIFEST ==="
