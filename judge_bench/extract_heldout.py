"""Extract every target response from the held-out runs into judge_bench/heldout_cases.jsonl.

Each case is pre-labelled by the rules in bench.py (SUCCESS / NOT) as a
starting point only: a human must check each label before the judges are scored.
Run: python3 judge_bench/extract_heldout.py
"""
import json, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
src = (HERE / "bench.py").read_text()
# reuse the rules without importing pyrit
ns: dict = {"re": re}
exec(src[src.index("RULES = ["):src.index("def _norm")], ns)

cases = []
for line in (HERE / "heldout_runs.txt").read_text().split("\n"):
    if not line.strip():
        continue
    run, target = line.split(" ", 1)
    for f in sorted((HERE.parent / "evidence" / "runs" / run).glob("pyrit-*.txt")):
        kind = "crescendo" if "crescendo" in f.name else "tap"
        for sec in f.read_text().split("=" * 72)[1:]:
            m = re.search(r"OBJECTIVE: (.+)", sec)
            if not m:
                continue
            obj = m.group(1).strip()
            for k, turn in enumerate(re.split(r"\n(?=assistant:)", sec)[1:]):
                resp = re.sub(r"^assistant:\s*", "", turn)
                resp = re.split(r"\nuser:\n", resp)[0]
                resp = re.split(r"\n(?:score:|Converted value:)", resp)[0].strip()  # drop PyRIT's own scorer text
                if len(resp) < 20:
                    continue
                cases.append({
                    "id": f"H{len(cases):03d}", "source": f"{run}/{kind}", "target": target,
                    "label": "SUCCESS" if ns["rule_verdict"](obj, resp) else "NOT",
                    "why": "PRE-LABEL by rules; unchecked", "objective": obj, "response": resp,
                })
(HERE / "heldout_cases.jsonl").write_text("\n".join(json.dumps(c) for c in cases) + "\n")
from collections import Counter
print(len(cases), Counter((c["target"], c["label"]) for c in cases))
