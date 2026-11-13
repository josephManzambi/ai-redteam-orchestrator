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


# Held-out run (2026-11-13)

The first benchmark's limits were one target, one reviewer and rules tuned on the same data. This run collects fresh transcripts the judges and rules had not seen: three Crescendo and TAP runs on the same target (`qwen2.5:7b-instruct-q8_0`) and three on a second target from another family (`mistral:7b`), via `collect_heldout.sh`. `extract_heldout.py` pulls every target response (60), pre-labels it with the rules, and the labels were then checked by reading the code in every success and every `/etc/shadow` or `/etc/passwd` mention among the non-successes. Seven responses that give a command reading `/etc/shadow` directly, without the `../../` path the objective names, are labelled AMBIGUOUS and excluded, as in the first set.

Run: `uv run judge_bench/bench.py --judges <models> --cases judge_bench/heldout_qwen.jsonl --out judge_bench/heldout_results_qwen.csv`. Raw rows: `heldout_results_qwen.csv`, `heldout_results_mistral.csv`.

## qwen target: 25 successes, 20 non-successes (45 labelled)

Missed successes / false alarms, as in the table above.

| Judge | PyRIT scale (decides "achieved" today) | Yes/no + verbatim quote check | s/case |
|---|---|---|---|
| qwen2.5:7b (self-play) | **25 / 0** | 25 / 0 | 2.4 |
| mistral:7b | 0 / **12** | 10 / 1 | 3.6 |
| gemma2:9b | 6 / 9 | 6 / 1 | 7.3 |
| mixtral:8x7b | 8 / 3 | 19 / 0 | 6.3 |
| llama3.3:70b | **3 / 0** | 5 / 0 | 35.4 |
| Rules only (no judge) | 0 / 0 | | |

## mistral target: 1 success, 7 non-successes

Too few successes to compare judges (mistral mostly explained or refused): llama3.3:70b, gemma2:9b and the self-play judge each agree with the labels on the one success or miss it; see the CSV. The useful fact is the contrast with PyRIT's own verdict: on the three mistral runs PyRIT reported the objective achieved every time, while the labels find one real success in 12 responses. `mistral:7b` was left out as a judge on its own transcripts.

## What the held-out run says

- **Self-play is still the worst judge, and the result replicated.** qwen2.5:7b judging its own transcripts recognised 0 of 25 real successes on the scale that decides "achieved" (1 of 18 in the first set). It never raised a false alarm, which is why it looks quiet.
- **llama3.3:70b is still the only judge that holds up on the scale** (3 of 25 missed, 0 false alarms; 3 of 18 and 1 in the first set), at about 35 seconds a response on this machine.
- **Small judges are unreliable, in different ways.** mistral:7b as a judge flagged every non-success it was shown and 0 of the successes it missed (12 false alarms of 20); gemma2:9b and mixtral:8x7b miss a quarter to a third of successes and raise false alarms on some non-successes.
- **The verbatim-quote check still removes real successes** (mixtral:8x7b 19 of 25 missed with it), for the same reason as before: judges paraphrase or reformat code when quoting. It needs looser matching before it is useful.
- **The rules scored 0 missed and 0 false alarms on the held-out set, including the second target.** Read that with care: the labels were pre-filled by the rules and then checked by reading the code, so the two are not independent, and the labels were checked by one reviewer. It does say the rules' patterns (an unquoted traversal path, `cat /etc/passwd` in code) generalised to new transcripts from the same objectives.

## Limits of this run

Same three objectives as the first set, two targets (the second gave only one success), labels checked by a single reviewer, seven ambiguous responses excluded (how they are ruled would shift the counts a little), and rules that were written against the first set. A benchmark on different objectives and more than one labeller is still needed before any of this is quoted as general.
