# Judge benchmark: first results (2026-10-31)

45 target responses taken from four real Layer 3 runs (target `qwen2.5:7b-instruct-q8_0`), labeled by hand against one written definition (see `bench.py`, `GROUNDED_SYSTEM`): 18 successes, 20 non-successes, 7 ambiguous (excluded from the numbers). Each label carries its reason in `labeled_turns.jsonl`.

Run: `uv run judge_bench/bench.py --judges <models>`. Raw rows: `results.csv`.

## Missed successes / false alarms (out of 18 / 20)

| Judge | PyRIT scale (what decides "achieved" today) | Yes/no judge | Yes/no + verbatim quote check | s/case |
|---|---|---|---|---|
| qwen2.5:7b (self-play) | **17 / 0** | 18 / 0 | 18 / 0 | 3.6 |
| mistral:7b | 4 / **10** | 9 / 1 | 13 / 1 | 3.1 |
| gemma2:9b | 7 / 4 | 8 / 0 | 12 / 0 | 3.6 |
| mixtral:8x7b | 11 / 2 | 16 / 0 | 18 / 0 | 5.3 |
| llama3.3:70b | **3 / 1** | **4 / 0** | 12 / 0 | 28.5 |
| Rules only (no judge) | | | 0 / 0 | — |

## What it shows

- **Self-play is the worst judge by far.** Judging its own transcripts, qwen2.5:7b recognised 1 of 18 real successes. This quantifies issue #27.
- **Small judges are unreliable on PyRIT's scale.** mistral:7b raises false alarms on half the non-successes; gemma2:9b and mixtral:8x7b miss many real successes.
- **llama3.3:70b is the only judge that holds up** (34/38 on the scale, 34/38 as a yes/no judge with no false alarms), at about 28 s per response.
- **The verbatim-quote check, as written, only removed true successes.** Every "yes" it rejected was a real success: judges paraphrase or reformat code when quoting. It needs looser matching before it is useful.
- **The rules score 38/38, but they were written against this same set**, so that number is optimistic until checked on new transcripts.

## Limits of this benchmark

One target model, three objectives, labels by one reviewer, and rules tuned on the same data. A held-out set from fresh runs (ideally a second target model) is needed before any of these numbers is quoted as general.
