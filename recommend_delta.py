#!/usr/bin/env python3
"""
recommend_delta.py — label-free recommendation of the radius δ for MAPTER's
binary-to-binary correlation, from the percentiles of unrelated-code distances.

Method (Sec. "Choosing the Radius" of the evaluation):
  1. Sample random pairs of binaries (almost all unrelated in practice). For up to
     `n_query` functions of the first binary, take the distance to the nearest
     function of the second. These are the "unrelated distances".
  2. The k-th percentile of those distances is the radius at which k% of functions
     meet unrelated code by chance. Percentiles give a common scale across maps,
     whose raw units are arbitrary.
  3. Detection peaks between the 1st and the 50th percentile on every map we
     examined (BinaryCorp-26M, BinaryCorp-3M, APT19, APT21) and vanishes beyond
     it. The recommended search range is therefore [first non-zero percentile,
     p50]; identical code has distance 0, so the lower end skips the zero share.
  4. Candidates are the radii at a few percentiles covering both ends of the
     range (default: lower end, 5, 20, 40, 50). Pick among them with a few known
     relations or by inspecting the dendrograms: too large a radius merges most
     binaries into a few heavily interconnected groups.

Input: a pickled DataFrame with columns x, y, binary_name (the APT19/APT21
format, e.g. SAFEtorch/dataPickledAllFunctions/APT_19.pkl), or a DataFrame /
arrays passed directly from the app.

Library use (e.g. from a Dash callback):
    from recommend_delta import load_pkl, recommend
    coords, bnames = load_pkl("APT_19.pkl")
    rec = recommend(coords, bnames)            # dict, JSON-serialisable
    rec["candidates"]   -> [{"percentile": 5, "delta": 0.0007}, ...]
    rec["curve"]        -> {"percentile": [...], "delta": [...]}  for plotting
    position_of(0.2, rec)                      -> percentile of a given δ
    in_range(0.2, rec)                         -> 'below' | 'inside' | 'above'

CLI:
    python recommend_delta.py APT_19.pkl [--delta 0.2] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Iterable, Optional

import numpy as np
import pandas as pd
from scipy.spatial import cKDTree

DEFAULT_PERCENTILES = (5, 20, 40, 50)   # candidates inside the range, plus its lower end
UPPER_PCT = 50                          # detection vanishes beyond this on every map examined
CURVE_PCTS = tuple(range(0, 101))       # resolution of the curve returned for plotting


# --------------------------------------------------------------------------- input
def load_pkl(path: str | Path) -> tuple[np.ndarray, np.ndarray]:
    """Read a pickled DataFrame with columns x, y, binary_name (APT19/APT21 format)."""
    return from_dataframe(pd.read_pickle(path))


def from_dataframe(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """(coords float64 (N, 2), binary names (N,)) from a DataFrame with x, y, binary_name."""
    missing = {"x", "y", "binary_name"} - set(df.columns)
    if missing:
        raise KeyError(f"missing columns {sorted(missing)}; got {list(df.columns)}")
    coords = np.ascontiguousarray(df[["x", "y"]].to_numpy(), dtype=np.float64)
    return coords, df["binary_name"].to_numpy().astype(str)


# --------------------------------------------------------------------------- method
def unrelated_distances(coords: np.ndarray, bnames: np.ndarray, n_pairs: int = 2000,
                        n_query: int = 200, seed: int = 42) -> np.ndarray:
    """
    Distances from functions of a random binary A to the nearest function of a
    random other binary B, pooled over `n_pairs` random (A, B) pairs. Same
    estimator as predict_delta.pairwise_binary_1nn.
    """
    rng = np.random.default_rng(seed)
    codes, inv = np.unique(bnames, return_inverse=True)
    if len(codes) < 2:
        raise ValueError("need at least two binaries")
    order = np.argsort(inv, kind="stable")
    starts = np.searchsorted(inv[order], np.arange(len(codes)))
    ends = np.append(starts[1:], len(order))
    trees: dict[int, cKDTree] = {}
    out = []
    for _ in range(n_pairs):
        a, b = rng.choice(len(codes), size=2, replace=False)
        if b not in trees:
            trees[b] = cKDTree(coords[order[starts[b]:ends[b]]])
        rows_a = order[starts[a]:ends[a]]
        if len(rows_a) > n_query:
            rows_a = rng.choice(rows_a, size=n_query, replace=False)
        out.append(trees[b].query(coords[rows_a], k=1)[0])
    return np.concatenate(out)


def recommend(coords: np.ndarray, bnames: np.ndarray,
              percentiles: Iterable[int] = DEFAULT_PERCENTILES, n_pairs: int = 2000,
              n_query: int = 200, seed: int = 42, n_boot: int = 200) -> dict:
    """
    Recommend the search range and candidate radii for δ. Returns a JSON-serialisable
    dict: zero share, range (percentiles and radii), candidates with bootstrap 95%
    intervals, and the full percentile curve for plotting.
    """
    d = unrelated_distances(coords, bnames, n_pairs, n_query, seed)
    zero_share = float(np.mean(d == 0))
    q = np.percentile(d, CURVE_PCTS)
    # lower end: first integer percentile (>= 1) whose radius is non-zero
    lower_pct = next((p for p in CURVE_PCTS[1:] if q[p] > 0), UPPER_PCT)
    cand_pcts = sorted({lower_pct, *[p for p in percentiles if lower_pct <= p <= UPPER_PCT]})

    rng = np.random.default_rng(seed + 1)
    boots = np.array([np.percentile(rng.choice(d, size=len(d), replace=True), cand_pcts)
                      for _ in range(n_boot)]) if n_boot else None
    candidates = []
    for i, p in enumerate(cand_pcts):
        c = {"percentile": int(p), "delta": float(np.percentile(d, p))}
        if boots is not None:
            c["ci95"] = [float(np.percentile(boots[:, i], 2.5)), float(np.percentile(boots[:, i], 97.5))]
        candidates.append(c)

    return {
        "n_functions": int(len(coords)),
        "n_binaries": int(len(np.unique(bnames))),
        "n_distances": int(len(d)),
        "zero_share": zero_share,
        "range": {"lower_percentile": int(lower_pct), "upper_percentile": UPPER_PCT,
                  "lower_delta": float(q[lower_pct]), "upper_delta": float(q[UPPER_PCT])},
        "candidates": candidates,
        "curve": {"percentile": list(CURVE_PCTS), "delta": [float(v) for v in q]},
        "params": {"n_pairs": n_pairs, "n_query": n_query, "seed": seed, "n_boot": n_boot},
        "note": ("Search delta between the first non-zero percentile and the 50th of the unrelated "
                 "distances; test candidates at both ends and choose with known relations or by "
                 "inspecting the dendrograms (too large a radius merges binaries into a few "
                 "interconnected groups). Heuristic validated on four maps, not a guarantee."),
    }


def position_of(delta: float, rec: dict) -> Optional[float]:
    """Percentile of a given δ on the recommendation's curve (log-interpolated); None if off-curve."""
    p, v = rec["curve"]["percentile"], rec["curve"]["delta"]
    if delta <= 0 or delta > v[-1]:
        return None
    first = next(i for i, x in enumerate(v) if x > 0)
    if delta < v[first]:
        return 100.0 * rec["zero_share"]          # only identical code is this close
    for i in range(first + 1, len(v)):
        if v[i - 1] <= delta <= v[i]:
            if v[i] == v[i - 1]:
                return float(p[i])
            return p[i - 1] + (p[i] - p[i - 1]) * math.log(delta / v[i - 1]) / math.log(v[i] / v[i - 1])
    return float(p[first])


def in_range(delta: float, rec: dict) -> str:
    """Where a given δ falls relative to the recommended search range."""
    r = rec["range"]
    return "below" if delta < r["lower_delta"] else "above" if delta > r["upper_delta"] else "inside"


# --------------------------------------------------------------------------- CLI
def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pkl", help="pickled DataFrame with columns x, y, binary_name")
    ap.add_argument("--percentiles", type=int, nargs="+", default=list(DEFAULT_PERCENTILES))
    ap.add_argument("--n-pairs", type=int, default=2000)
    ap.add_argument("--n-query", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-boot", type=int, default=200)
    ap.add_argument("--delta", type=float, nargs="*", default=[], help="report the percentile of these radii")
    ap.add_argument("--json", help="write the full recommendation to this file")
    a = ap.parse_args(argv)

    coords, bnames = load_pkl(a.pkl)
    rec = recommend(coords, bnames, a.percentiles, a.n_pairs, a.n_query, a.seed, a.n_boot)
    r = rec["range"]
    print(f"{Path(a.pkl).name}: {rec['n_functions']} functions, {rec['n_binaries']} binaries, "
          f"{rec['n_distances']} unrelated distances; identical code {100 * rec['zero_share']:.1f}%")
    print(f"search range: p{r['lower_percentile']}–p{r['upper_percentile']} = "
          f"{r['lower_delta']:.4g} – {r['upper_delta']:.4g}")
    print("candidates:")
    for c in rec["candidates"]:
        ci = f"  (95% CI {c['ci95'][0]:.4g}–{c['ci95'][1]:.4g})" if "ci95" in c else ""
        print(f"  p{c['percentile']:<3} delta = {c['delta']:.4g}{ci}")
    for x in a.delta:
        pos = position_of(x, rec)
        if pos is None:
            where = "outside the curve"
        else:
            side = ("inside the range" if r["lower_delta"] <= x <= r["upper_delta"]
                    else "below the range" if x < r["lower_delta"] else "above the range")
            where = f"p{pos:.0f}  ({side})"
        print(f"delta = {x:g} -> {where}")
    if a.json:
        Path(a.json).write_text(json.dumps(rec, indent=2))
        print(f"written {a.json}")


if __name__ == "__main__":
    main()
