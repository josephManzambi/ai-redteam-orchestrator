"""The order in which repositories are walked, and the split (PROTOCOL.md,
"Sample and split").

Repositories are put in a random order with the published seed, separately for
TypeScript and Python, and the two lists are interleaved in proportion to their
size in the frame. Walking that order, the first 500 with an extractable tool
are kept; odd positions are the development set, even positions the held-out
set.

The order depends only on the seed and the repository names, through SHA-256,
so any language or Python version reproduces it.
"""
from __future__ import annotations

import hashlib

SEED = 20261114
TARGET = 500
STRATA = ("typescript", "python")


def _rank(seed: int, repo: str) -> str:
    return hashlib.sha256(f"{seed}:{repo}".encode("utf-8")).hexdigest()


def order(frame: dict[str, dict], seed: int = SEED) -> list[str]:
    """Every repository of the frame, in walking order."""
    lists = {s: sorted((r for r, v in frame.items() if v["stratum"] == s), key=lambda r: _rank(seed, r)) for s in STRATA}
    sizes = {s: len(lists[s]) for s in STRATA}
    taken = {s: 0 for s in STRATA}
    out: list[str] = []
    for _ in range(sum(sizes.values())):
        # Take from the stratum that is furthest behind its share; a tie goes
        # to the first stratum named.
        s = min((s for s in STRATA if taken[s] < sizes[s]), key=lambda s: ((taken[s] + 0.5) / sizes[s], STRATA.index(s)))
        out.append(lists[s][taken[s]])
        taken[s] += 1
    return out


def split(kept: list[str]) -> dict[str, list[str]]:
    """Kept repositories, in walking order, into the two halves. Positions
    count from 1: odd is development, even is held-out."""
    return {"development": kept[0::2], "held_out": kept[1::2]}
