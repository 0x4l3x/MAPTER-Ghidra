#!/usr/bin/env python3
"""
MAPTER dimensionality reduction (CPU first, GPU optional)
=========================================================
Turns the per-binary SAFE embedding files (``<sha256>.pkl``, a DataFrame with
columns ``offset, embeddings, name, size``) into the 2-D function map the MAPTER
app draws: one DataFrame ``x, y, binary_name, offset, name, size, sha256``.

Methods (``method=``):

  tsne   (default) standardise -> PCA (95 % variance, at most 50 dims) -> t-SNE
         sweep over a few perplexities, the run with the best composite score
         (Spearman correlation of pairwise distances, penalised for outlier
         points; computed on a <= 2000 point subsample) is kept.
  umap   same, with a UMAP n_neighbors sweep (needs the optional ``umap-learn``;
         without it the run falls back to t-SNE and says so in ``df.attrs``).
  pca    the first two components of the standardised PCA (deterministic).
  fixed  the original MAPTER recipe (former reduce_dimensions.py): PCA(40) on the raw embeddings ->
         t-SNE(perplexity 50, learning_rate auto, init pca, random_state 1312).

Everything runs with numpy + scikit-learn on the CPU.  cuPy/cuML are used for
PCA / t-SNE / UMAP only when they import AND a CUDA device exists (any GPU
failure falls back to the CPU path); ``fixed`` is always CPU.

Parameters adapt to small inputs (perplexity < n, PCA dims <= min(n, d)); with
fewer than 5 functions a deterministic fallback layout is used.  The result is
rescaled so the 99th percentile of |x|, |y| is about 100 (the scale of the
shipped maps, which the app's thresholds and sliders assume).

Library use::

    from mapter import reduce_embeddings
    df = reduce_embeddings(Path("embeddings"), binary_names, method="tsne",
                           out_pkl=Path("reduced_raw.pkl"))

CLI::

    python mapter.py --embeddings-dir DIR [--binary-names names.json]
                     [--method tsne|umap|pca|fixed] [--seed 42] [--out reduced.pkl]
                     [--plots [--plots-dir DIR]] [--backend auto|cpu] [-v]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from pipeline.common import assign_binary_names, atomic_to_pickle

logger = logging.getLogger("mapter.reduce")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SEED = 42
METHODS = ("tsne", "umap", "pca", "fixed")
OUTPUT_COLUMNS = ["x", "y", "binary_name", "offset", "name", "size", "sha256"]

PCA_VARIANCE_THRESHOLD = 0.95
PCA_MAX_DIMS = 50                 # cap on the PCA dims fed to t-SNE / UMAP
MIN_POINTS_FOR_EMBEDDING = 5      # below this: deterministic fallback layout
MIN_POINTS_FOR_UMAP = 10

PERPLEXITY_GRID = [10, 30, 50, 100]
N_NEIGHBORS_UMAP = [15, 30, 50, 100]
UMAP_MIN_DIST = 0.1

SCORE_MAX_SAMPLE = 2_000          # points used for the pairwise-distance score
OUTLIER_IQR_SCALE = 3.0
TARGET_P99 = 100.0                # coordinates are rescaled so p99(|x|,|y|) ~ this

# 'fixed' = the original MAPTER recipe (former reduce_dimensions.py)
FIXED_PCA_DIMS = 40
FIXED_PERPLEXITY = 50
FIXED_SEED = 1312


class ReductionCancelled(RuntimeError):
    """Raised when the StopFlag is set between two sweep candidates."""


# ═══════════════════════════════════════════════════════════════════════════
# Loading the SAFE embedding files
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EmbeddingSet:
    """All functions of a run: ``X`` (N, D) float32 and one metadata row each
    (columns binary_name, offset, name, size, sha256)."""
    X: np.ndarray
    meta: pd.DataFrame
    n_files: int = 0
    skipped_files: Dict[str, str] = field(default_factory=dict)
    dropped_rows: int = 0


def normalize_offset(value: Any) -> Optional[str]:
    """Lowercase, unpadded ``0x`` hex of the loaded VA (``hex(int)``); None if
    the value cannot be read as an address."""
    if value is None:
        return None
    if isinstance(value, (bool, np.bool_)):
        return None
    if isinstance(value, (int, np.integer)):
        return hex(int(value))
    if isinstance(value, (float, np.floating)):
        return hex(int(value)) if np.isfinite(value) else None
    s = str(value).strip().lower()
    if not s:
        return None
    try:
        return hex(int(s, 16))  # int(.., 16) accepts the 0x prefix
    except ValueError:
        return None


def load_embeddings(embeddings_dir: Path,
                    binary_names: Optional[Dict[str, str]] = None) -> EmbeddingSet:
    """Read every ``<sha256>.pkl`` in ``embeddings_dir`` into arrays + metadata.

    ``binary_names`` maps sha256 -> binary_name; files whose sha256 is not in it
    are ignored (stale outputs of another run).  Without it the names come from
    :func:`pipeline.common.assign_binary_names`.  Rows with a missing, ragged or
    non-finite embedding, an unreadable offset, or a duplicate (binary_name,
    offset) are dropped (counted in ``dropped_rows``); unreadable files are
    recorded in ``skipped_files``.  Files are read in sorted order, so the row
    order is deterministic.
    """
    embeddings_dir = Path(embeddings_dir)
    files = sorted(embeddings_dir.glob("*.pkl"))
    if binary_names is None:
        binary_names = assign_binary_names(p.stem for p in files)
    names = {k.lower(): v for k, v in binary_names.items()}

    skipped: Dict[str, str] = {}
    metas: List[pd.DataFrame] = []
    arrays: List[np.ndarray] = []
    dim: Optional[int] = None
    dropped = 0
    n_files = 0

    for path in files:
        sha = path.stem.lower()
        if sha not in names:
            skipped[path.name] = "not in binary_names"
            logger.debug(f"ignoring {path.name}: sha256 not in the binary map")
            continue
        try:
            df = pd.read_pickle(path)
            if not {"offset", "embeddings"} <= set(df.columns):
                raise ValueError(f"missing columns (have {list(df.columns)})")
        except Exception as exc:  # corrupt / foreign pickle
            skipped[path.name] = f"unreadable: {exc}"
            logger.warning(f"skipping {path.name}: {exc}")
            continue
        n_files += 1

        rows, offs, keep_idx = [], [], []
        for i, (emb, off) in enumerate(zip(df["embeddings"].tolist(), df["offset"].tolist())):
            o = normalize_offset(off)
            if o is None or emb is None or not hasattr(emb, "__len__"):
                continue
            if dim is None and len(emb) > 0:
                dim = len(emb)
            if len(emb) != dim:
                continue
            rows.append(emb)
            offs.append(o)
            keep_idx.append(i)
        if not rows:
            dropped += len(df)
            skipped[path.name] = "no usable function rows"
            continue
        arr = np.asarray(rows, dtype=np.float32)
        finite = np.isfinite(arr).all(axis=1)
        sub = df.iloc[keep_idx]
        meta = pd.DataFrame({
            "binary_name": names[sha],
            "offset": offs,
            "name": sub["name"].to_numpy() if "name" in sub else np.nan,
            "size": pd.to_numeric(sub["size"], errors="coerce").to_numpy(dtype="float64")
            if "size" in sub else np.nan,
            "sha256": sha,
        })
        dropped += len(df) - int(finite.sum())
        metas.append(meta[finite].reset_index(drop=True))
        arrays.append(arr[finite])

    if not metas:
        raise ValueError(f"no usable embeddings in {embeddings_dir} "
                         f"({len(files)} .pkl files, {len(skipped)} skipped)")

    meta_all = pd.concat(metas, ignore_index=True)
    X = np.concatenate(arrays, axis=0)
    dup = meta_all.duplicated(subset=["binary_name", "offset"], keep="first").to_numpy()
    if dup.any():
        logger.warning(f"dropping {int(dup.sum())} duplicate (binary_name, offset) rows")
        dropped += int(dup.sum())
        meta_all, X = meta_all[~dup].reset_index(drop=True), X[~dup]
    logger.info(f"loaded {len(X)} functions x {X.shape[1]}D from {n_files} binaries "
                f"({dropped} rows dropped, {len(skipped)} files skipped)")
    return EmbeddingSet(X=X, meta=meta_all, n_files=n_files, skipped_files=skipped,
                        dropped_rows=dropped)


# ═══════════════════════════════════════════════════════════════════════════
# Compute backend (numpy / scikit-learn; cuPy + cuML only when usable)
# ═══════════════════════════════════════════════════════════════════════════

_GPU_CACHE: Dict[str, Any] = {}


def _gpu_modules() -> Optional[Dict[str, Any]]:
    """cupy/cuml modules when both import and a CUDA device exists, else None."""
    if "mods" not in _GPU_CACHE:
        mods = None
        try:
            import cupy as cp
            from cuml import TSNE as cuTSNE
            from cuml.decomposition import PCA as cuPCA
            if cp.cuda.runtime.getDeviceCount() < 1:
                raise RuntimeError("no CUDA device")
            mods = {"cp": cp, "TSNE": cuTSNE, "PCA": cuPCA}
            try:
                from cuml.manifold import UMAP as cuUMAP
                mods["UMAP"] = cuUMAP
            except Exception:
                pass
        except Exception as exc:
            logger.debug(f"GPU backend unavailable: {exc}")
        _GPU_CACHE["mods"] = mods
    return _GPU_CACHE["mods"]


class Backend:
    """PCA / t-SNE / UMAP on the best available hardware.  A GPU error on any
    call is logged and that call is redone on the CPU."""

    def __init__(self, prefer: str = "auto"):
        self.gpu = _gpu_modules() if prefer == "auto" else None
        self.name = "cuml-gpu" if self.gpu else "cpu"

    def _to_np(self, a: Any) -> np.ndarray:
        cp = self.gpu["cp"]
        if isinstance(a, cp.ndarray):
            return cp.asnumpy(a)
        if hasattr(a, "values"):
            v = a.values
            return cp.asnumpy(v) if isinstance(v, cp.ndarray) else np.asarray(v)
        return np.asarray(a)

    def pca(self, Xs: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Full-rank PCA -> (scores (N, k), explained_variance_ratio (k,),
        mean (D,), components (k, D)) with k = min(N, D)."""
        k = min(Xs.shape)
        if self.gpu:
            try:
                p = self.gpu["PCA"](n_components=k)
                Z = self._to_np(p.fit_transform(self.gpu["cp"].asarray(Xs, dtype="float32")))
                return (Z, self._to_np(p.explained_variance_ratio_), self._to_np(p.mean_),
                        self._to_np(p.components_))
            except Exception as exc:
                logger.warning(f"GPU PCA failed ({exc}); using CPU")
        from sklearn.decomposition import PCA
        p = PCA(n_components=k, svd_solver="full")
        Z = p.fit_transform(Xs)
        return Z, p.explained_variance_ratio_, p.mean_, p.components_

    def tsne(self, Z: np.ndarray, perplexity: float, seed: int) -> np.ndarray:
        if self.gpu:
            try:
                t = self.gpu["TSNE"](n_components=2, perplexity=float(perplexity), random_state=seed)
                return self._to_np(t.fit_transform(self.gpu["cp"].asarray(Z, dtype="float32")))
            except Exception as exc:
                logger.warning(f"GPU t-SNE failed ({exc}); using CPU")
        from sklearn.manifold import TSNE
        return TSNE(n_components=2, perplexity=float(perplexity), learning_rate="auto",
                    init="pca", random_state=seed, n_jobs=-1).fit_transform(Z)

    def umap(self, Z: np.ndarray, n_neighbors: int, seed: int) -> np.ndarray:
        if self.gpu and "UMAP" in self.gpu:
            try:
                u = self.gpu["UMAP"](n_components=2, n_neighbors=n_neighbors,
                                     min_dist=UMAP_MIN_DIST, random_state=seed)
                return self._to_np(u.fit_transform(self.gpu["cp"].asarray(Z, dtype="float32")))
            except Exception as exc:
                logger.warning(f"GPU UMAP failed ({exc}); using CPU")
        import umap  # umap-learn
        return umap.UMAP(n_components=2, n_neighbors=n_neighbors, min_dist=UMAP_MIN_DIST,
                         random_state=seed).fit_transform(Z)


def umap_available() -> bool:
    """True when umap-learn (or cuML UMAP on a GPU) can be used."""
    gpu = _gpu_modules()
    if gpu and "UMAP" in gpu:
        return True
    try:
        import umap  # noqa: F401
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Metrics (CPU port of compute_simple_metrics_gpu)
# ═══════════════════════════════════════════════════════════════════════════

def composite_metrics(X_high: np.ndarray, X_2d: np.ndarray, seed: int = SEED,
                      max_sample: int = SCORE_MAX_SAMPLE) -> Dict[str, float]:
    """Quality of a 2-D embedding of ``X_high``.

    - spearman_rho    : rank correlation of pairwise distances on a random
                        subsample of <= ``max_sample`` points
    - outlier_frac    : fraction of points farther than q3 + 3*IQR from the 2-D
                        centroid (all points)
    - outlier_penalty : 1 - exp(-6 * outlier_frac)
    - composite_score : spearman_rho * (1 - outlier_penalty)
    """
    from scipy.spatial.distance import pdist
    from scipy.stats import rankdata

    n = len(X_2d)
    m = min(n, max_sample)
    idx = np.sort(np.random.default_rng(seed).choice(n, size=m, replace=False)) if m < n \
        else np.arange(n)
    rho = float("nan")
    if m >= 3:
        d_high = pdist(np.asarray(X_high[idx], dtype=np.float64))
        d_low = pdist(np.asarray(X_2d[idx], dtype=np.float64))
        rh = rankdata(d_high) - (len(d_high) + 1) / 2.0
        rl = rankdata(d_low) - (len(d_low) + 1) / 2.0
        denom = float(np.sqrt((rh ** 2).sum() * (rl ** 2).sum()))
        rho = float((rh * rl).sum() / denom) if denom > 0 else 0.0

    dists = np.linalg.norm(X_2d - X_2d.mean(axis=0), axis=1)
    q1, q3 = np.percentile(dists, [25.0, 75.0])
    outlier_frac = float((dists > q3 + OUTLIER_IQR_SCALE * (q3 - q1)).sum() / max(n, 1))
    penalty = 1.0 - float(np.exp(-6.0 * outlier_frac))
    return {"spearman_rho": rho, "outlier_penalty": penalty, "outlier_frac": outlier_frac,
            "composite_score": rho * (1.0 - penalty) if np.isfinite(rho) else float("nan")}


def _best_key(scores: Dict[Any, Dict[str, float]]) -> Any:
    """Key with the highest composite score (NaN counts as worst; ties keep the
    first, i.e. smallest, parameter)."""
    def val(k):
        v = scores[k]["composite_score"]
        return v if np.isfinite(v) else -np.inf
    return max(scores, key=val)


# ═══════════════════════════════════════════════════════════════════════════
# Adaptive parameters
# ═══════════════════════════════════════════════════════════════════════════

def adaptive_perplexities(n: int) -> List[float]:
    """Perplexity grid for ``n`` points: each value below n/3 (sklearn needs
    perplexity < n; much above n/3 the map degenerates), at most 4 values and
    two above 3000 points and one above 20000 to bound the run time."""
    cap = max(1.0, (n - 1) / 3.0)
    grid: List[float] = [p for p in PERPLEXITY_GRID if p <= cap]
    if n > 20_000:
        grid = [p for p in grid if p == 50] or grid[-1:]
    elif n > 3_000:
        grid = [p for p in grid if p in (30, 50)] or grid[-1:]
    if not grid:
        grid = [float(round(min(30.0, cap), 2))]
    return grid


def adaptive_n_neighbors(n: int) -> List[int]:
    """UMAP n_neighbors grid: every value <= n - 1 (a single value when none fit)."""
    grid = [k for k in N_NEIGHBORS_UMAP if k <= n - 1]
    if n > 20_000:
        grid = [k for k in grid if k in (30, 100)] or grid[-1:]
    return grid or [max(2, n - 1)]


# ═══════════════════════════════════════════════════════════════════════════
# Reduction core
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ReduceResult:
    """Raw 2-D coordinates (before rescaling) and a JSON-able description."""
    coords: np.ndarray
    info: Dict[str, Any]
    candidates: Dict[Any, np.ndarray] = field(default_factory=dict)
    evr: Optional[np.ndarray] = None
    pca_model: Optional[Dict[str, np.ndarray]] = None


def scaler_params(X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Per-dimension mean and std (float64; std 0 -> 1 so constant dims are only centred)."""
    mean = X.mean(axis=0, dtype=np.float64)
    std = X.std(axis=0, dtype=np.float64)
    std[std == 0] = 1.0
    return mean, std


def standardise(X: np.ndarray) -> np.ndarray:
    """Z-score per dimension."""
    mean, std = scaler_params(X)
    return ((X - mean) / std).astype(np.float32)


def circle_layout(n: int) -> np.ndarray:
    """Deterministic layout on the unit circle (n == 1 -> the origin)."""
    if n <= 1:
        return np.zeros((n, 2))
    ang = 2.0 * np.pi * np.arange(n) / n
    return np.column_stack([np.cos(ang), np.sin(ang)])


def small_layout(X: np.ndarray) -> np.ndarray:
    """Deterministic layout for fewer than MIN_POINTS_FOR_EMBEDDING points: the
    first two principal axes of the data; a circle when the points coincide."""
    n = len(X)
    if n <= 1:
        return np.zeros((n, 2))
    Xc = np.asarray(X, dtype=np.float64)
    Xc = Xc - Xc.mean(axis=0)
    if not np.any(np.abs(Xc) > 1e-9):
        return circle_layout(n)
    U, S, _ = np.linalg.svd(Xc, full_matrices=False)
    xy = np.zeros((n, 2))
    k = min(2, U.shape[1])
    xy[:, :k] = U[:, :k] * S[:k]
    # sign convention so the output does not depend on the SVD's arbitrary signs
    for j in range(k):
        if xy[np.argmax(np.abs(xy[:, j])), j] < 0:
            xy[:, j] = -xy[:, j]
    return xy


def _pca_dims(evr: np.ndarray, n_full: int) -> Tuple[int, float]:
    """Components for PCA_VARIANCE_THRESHOLD of the variance, clipped to
    [2, min(PCA_MAX_DIMS, n_full)]; also returns the variance they explain."""
    evr = np.nan_to_num(np.asarray(evr, dtype=np.float64))
    cum = np.cumsum(evr)
    k = int(np.searchsorted(cum, PCA_VARIANCE_THRESHOLD) + 1)
    k = max(2, min(k, PCA_MAX_DIMS, n_full))
    return k, float(cum[k - 1]) if len(cum) >= k else float(cum[-1])


def _is_degenerate(Z: np.ndarray) -> bool:
    """True when the (PCA-projected) points have no spread, i.e. identical
    embeddings; sklearn's t-SNE crashes (segfault) on such input."""
    return not np.any(np.abs(Z) > 1e-7)


def _stopped(stop: Any) -> bool:
    return stop is not None and stop.is_set()


def _progress(status: Any, message: str) -> None:
    logger.info(message)
    if status is not None:
        status.progress(message=message)


def _run_fixed(X: np.ndarray, info: Dict[str, Any]) -> ReduceResult:
    """Original MAPTER recipe (former reduce_dimensions.py): PCA(40) on the raw embeddings, t-SNE perplexity 50,
    random_state 1312.  The PCA gets the same random_state, which makes the
    script's otherwise unseeded randomized solver reproducible (it equals the
    script run after ``np.random.seed(1312)``).  Perplexity 50 needs n > 50;
    below that it is lowered to (n - 1) / 3."""
    from sklearn.decomposition import PCA
    from sklearn.manifold import TSNE

    n = len(X)
    n_pca = min(FIXED_PCA_DIMS, n, X.shape[1])
    perplexity = float(FIXED_PERPLEXITY) if n > FIXED_PERPLEXITY else max(1.0, (n - 1) / 3.0)
    Z = PCA(n_components=n_pca, random_state=FIXED_SEED).fit_transform(X.astype(np.float64))
    info["seed"], info["backend"] = FIXED_SEED, "cpu"
    if _is_degenerate(Z - Z.mean(axis=0)):
        info["method_used"] = "layout"
        info["notes"].append("all embeddings are identical: circle layout")
        return ReduceResult(coords=circle_layout(len(X)), info=info)
    xy = TSNE(n_components=2, perplexity=perplexity, learning_rate="auto", init="pca",
              random_state=FIXED_SEED).fit_transform(Z)
    info["params"] = {"pca_components": n_pca, "perplexity": perplexity, "seed": FIXED_SEED,
                      "standardised": False}
    return ReduceResult(coords=xy, info=info)


def reduce_matrix(X: np.ndarray, method: str = "tsne", seed: int = SEED, backend: str = "auto",
                  status: Any = None, stop: Any = None) -> ReduceResult:
    """Reduce embeddings ``X`` (N, D) to 2-D with ``method``; see the module
    docstring.  Returns raw (unscaled) coordinates plus a description of what
    was run (``info``: method_requested/method_used, params, scores, pca, ...).
    """
    if method not in METHODS:
        raise ValueError(f"unknown method {method!r} (choose from {', '.join(METHODS)})")
    X = np.asarray(X, dtype=np.float32)
    if X.ndim != 2 or len(X) == 0:
        raise ValueError(f"embeddings must be a non-empty (N, D) array, got shape {X.shape}")
    n = len(X)
    info: Dict[str, Any] = {"method_requested": method, "method_used": method, "n_points": n,
                            "n_dims": int(X.shape[1]), "seed": seed, "notes": []}

    if n < MIN_POINTS_FOR_EMBEDDING:
        info["method_used"] = "layout"
        info["notes"].append(f"only {n} function(s): deterministic fallback layout")
        info["backend"] = "cpu"
        return ReduceResult(coords=small_layout(X), info=info)

    if method == "fixed":
        _progress(status, f"fixed reduction (PCA {FIXED_PCA_DIMS} -> t-SNE perplexity "
                          f"{FIXED_PERPLEXITY}) on {n} functions")
        res = _run_fixed(X, info)
        return res

    if method == "umap" and (n < MIN_POINTS_FOR_UMAP or not umap_available()):
        reason = (f"{n} points are too few for UMAP" if n < MIN_POINTS_FOR_UMAP
                  else "umap-learn is not installed (pip install umap-learn)")
        logger.warning(f"{reason}; using t-SNE instead")
        info["notes"].append(f"{reason}: used t-SNE")
        method = info["method_used"] = "tsne"

    be = Backend(backend)
    info["backend"] = be.name

    # standardise -> PCA (95 % variance, capped)
    Xs = standardise(X)
    Z_full, evr, p_mean, p_comp = be.pca(Xs)
    k, cumvar = _pca_dims(evr, min(Xs.shape))
    Z = Z_full[:, :k].astype(np.float32)
    if Z.shape[1] < 2:
        Z = np.hstack([Z, np.zeros((n, 2 - Z.shape[1]), dtype=np.float32)])
    info["pca"] = {"n_components": k, "cumulative_variance": cumvar,
                   "variance_threshold": PCA_VARIANCE_THRESHOLD, "max_dims": PCA_MAX_DIMS}
    s_mean, s_std = scaler_params(X)
    pca_model = {"scaler_mean": s_mean.astype(np.float32), "scaler_std": s_std.astype(np.float32),
                 "pca_mean": np.asarray(p_mean, np.float32),
                 "components": np.asarray(p_comp[:k], np.float32),
                 "explained_variance_ratio": np.asarray(evr[:k], np.float32)}
    _progress(status, f"PCA {X.shape[1]}D -> {k}D ({cumvar * 100:.1f}% variance)")

    if _is_degenerate(Z):  # identical embeddings: nothing to project
        info["method_used"] = "layout"
        info["notes"].append("all embeddings are identical: circle layout")
        return ReduceResult(coords=circle_layout(n), info=info, evr=evr, pca_model=pca_model)

    result = ReduceResult(coords=np.zeros((n, 2)), info=info, evr=evr, pca_model=pca_model)

    if method == "pca":
        xy = np.ascontiguousarray(Z[:, :2], dtype=np.float64)
        info["params"] = {"components": [0, 1], "explained_variance": float(np.nansum(evr[:2]))}
        info["scores"] = {"pca": composite_metrics(Z, xy, seed)}
        result.coords = xy
        return result

    # sweep (t-SNE perplexity or UMAP n_neighbors), scored on a subsample
    if method == "tsne":
        grid: List[Any] = adaptive_perplexities(n)
        param_name = "perplexity"
        run = lambda p: be.tsne(Z, p, seed)  # noqa: E731
    else:
        grid = adaptive_n_neighbors(n)
        param_name = "n_neighbors"
        run = lambda p: be.umap(Z, p, seed)  # noqa: E731

    scores: Dict[Any, Dict[str, float]] = {}
    cands: Dict[Any, np.ndarray] = {}
    for i, p in enumerate(grid, 1):
        if _stopped(stop):
            raise ReductionCancelled("cancelled during the parameter sweep")
        _progress(status, f"{method} {param_name}={p} ({i}/{len(grid)}) on {n} functions")
        t0 = time.time()
        try:
            xy = np.asarray(run(p), dtype=np.float64)
            if xy.shape != (n, 2) or not np.isfinite(xy).all():
                raise ValueError("non-finite or mis-shaped embedding")
        except Exception as exc:
            logger.warning(f"{method} {param_name}={p} failed: {exc}")
            info["notes"].append(f"{param_name}={p} failed: {exc}")
            continue
        sc = composite_metrics(Z, xy, seed)
        scores[p], cands[p] = sc, xy
        logger.info(f"  {param_name}={p}: spearman={sc['spearman_rho']:.3f} "
                    f"outlier_frac={sc['outlier_frac']:.3f} composite={sc['composite_score']:.3f} "
                    f"({time.time() - t0:.1f}s)")

    result.candidates = cands
    info["sweep"] = {"parameter": param_name, "grid": [float(g) for g in grid]}
    info["scores"] = {str(p): s for p, s in scores.items()}
    if not cands:
        logger.warning(f"every {method} run failed; falling back to the PCA 2-D layout")
        info["notes"].append(f"every {method} run failed: PCA 2-D layout")
        info["method_used"] = "pca"
        result.coords = np.ascontiguousarray(Z[:, :2], dtype=np.float64)
        info["params"] = {"components": [0, 1]}
        return result

    best = _best_key(scores)
    info["params"] = {param_name: float(best) if method == "tsne" else int(best),
                      "pca_components": k}
    if method == "umap":
        info["params"]["min_dist"] = UMAP_MIN_DIST
    result.coords = cands[best]
    logger.info(f"best {param_name}: {best} (composite={scores[best]['composite_score']:.4f})")
    return result


def rescale_coords(xy: np.ndarray, target: float = TARGET_P99,
                   center: bool = False) -> Tuple[np.ndarray, float]:
    """Scale (and optionally median-centre) coordinates so the 99th percentile
    of |x|, |y| equals ``target``.  Returns (coords, scale); a degenerate cloud
    (p99 == 0) is returned unscaled."""
    xy = np.asarray(xy, dtype=np.float64)
    if center:
        xy = xy - np.median(xy, axis=0)
    p99 = float(np.percentile(np.abs(xy).ravel(), 99))
    if not np.isfinite(p99) or p99 <= 1e-12:
        return xy, 1.0
    scale = target / p99
    return xy * scale, scale


# ═══════════════════════════════════════════════════════════════════════════
# Public entry point
# ═══════════════════════════════════════════════════════════════════════════

def reduce_embeddings(embeddings_dir: Path, binary_names: Optional[Dict[str, str]] = None,
                      method: str = "tsne", seed: int = SEED, out_pkl: Optional[Path] = None,
                      status: Any = None, stop: Any = None, *, backend: str = "auto",
                      rescale: bool = True, plots_dir: Optional[Path] = None,
                      pca_model_path: Optional[Path] = None) -> pd.DataFrame:
    """Reduce the SAFE embeddings in ``embeddings_dir`` (``<sha256>.pkl``) to the
    MAPTER function map.

    Returns a DataFrame with columns ``x, y`` (float32), ``binary_name, offset,
    name, sha256`` (str) and ``size`` (float64, NaN allowed).  ``binary_names``
    maps sha256 -> binary_name (default: ``assign_binary_names``).  With
    ``out_pkl`` the frame is also written atomically.  What was run is in
    ``df.attrs["mapter_reduce"]`` (method_requested / method_used, params,
    scores, pca, scale, backend, notes, elapsed seconds).

    ``status`` (pipeline.common.Status) receives progress messages; ``stop``
    (StopFlag) is checked between sweep candidates and raises
    :class:`ReductionCancelled`.  Raises ValueError when there is no embedding.
    """
    t0 = time.time()
    emb = load_embeddings(embeddings_dir, binary_names)
    if status is not None:
        status.progress(message=f"{len(emb.X)} functions from {emb.n_files} binaries")
    res = reduce_matrix(emb.X, method=method, seed=seed, backend=backend, status=status, stop=stop)

    used = res.info["method_used"]
    if rescale:
        # UMAP has no natural origin; t-SNE/PCA are centred already and 'fixed'
        # keeps the script's coordinates up to the scale factor
        xy, scale = rescale_coords(res.coords, center=(used == "umap"))
    else:
        xy, scale = np.asarray(res.coords, dtype=np.float64), 1.0
    res.info.update(scale=scale, rescaled=bool(rescale), n_binaries=int(emb.meta["binary_name"].nunique()),
                    n_functions=len(emb.X), n_files=emb.n_files, dropped_rows=emb.dropped_rows,
                    skipped_files=emb.skipped_files, elapsed_s=round(time.time() - t0, 2))

    df = pd.DataFrame({
        "x": xy[:, 0].astype(np.float32),
        "y": xy[:, 1].astype(np.float32),
        "binary_name": emb.meta["binary_name"].astype(object).to_numpy(),
        "offset": emb.meta["offset"].astype(object).to_numpy(),
        "name": emb.meta["name"].astype(object).to_numpy(),
        "size": emb.meta["size"].to_numpy(dtype="float64"),
        "sha256": emb.meta["sha256"].astype(object).to_numpy(),
    })[OUTPUT_COLUMNS]
    df.attrs["mapter_reduce"] = res.info

    if out_pkl is not None:
        atomic_to_pickle(df, Path(out_pkl))
        logger.info(f"wrote {out_pkl} ({len(df)} functions, method {used})")
    if pca_model_path is not None and res.pca_model is not None:
        np.savez(pca_model_path, **res.pca_model)
    if plots_dir is not None:
        try:
            make_plots(df, res, Path(plots_dir))
        except Exception as exc:  # plots are extras; never fail the run
            logger.warning(f"plots skipped: {exc}")
    return df


def pca_transform(X: np.ndarray, model_path: Path, n_components: Optional[int] = None) -> np.ndarray:
    """Project new 100-D SAFE embeddings with a saved PCA model (``--pca-model``).
    ``n_components=2`` gives coordinates in the space of the 'pca' embedding
    (before rescaling)."""
    m = np.load(model_path)
    Z = (np.asarray(X, np.float32) - m["scaler_mean"]) / m["scaler_std"]
    comps = m["components"] if n_components is None else m["components"][:n_components]
    return (Z - m["pca_mean"]) @ comps.T


# ═══════════════════════════════════════════════════════════════════════════
# Plots (optional: needs matplotlib)
# ═══════════════════════════════════════════════════════════════════════════

def make_plots(df: pd.DataFrame, res: ReduceResult, out_dir: Path) -> None:
    """PNGs of the map (coloured by binary), the PCA scree and, for sweeps, the
    score per parameter.  Needs matplotlib."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir.mkdir(parents=True, exist_ok=True)
    info = res.info
    cmap = plt.get_cmap("tab20")

    fig, ax = plt.subplots(figsize=(8, 7))
    codes, uniques = pd.factorize(df["binary_name"])
    ax.scatter(df["x"], df["y"], c=[cmap(c % 20) for c in codes], s=6, alpha=0.6, edgecolors="none")
    ax.set_title(f"MAPTER map: {info['method_used']} ({len(df)} functions)")
    ax.set_xlabel("x")
    ax.set_ylabel("y")
    handles = [plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=cmap(i % 20),
                          markersize=6, label=str(u)) for i, u in enumerate(uniques[:20])]
    if handles:
        ax.legend(handles=handles, fontsize=7, loc="best", framealpha=0.7)
    fig.tight_layout()
    fig.savefig(out_dir / "map.png", dpi=150)
    plt.close(fig)

    if res.evr is not None and info.get("pca"):
        evr = np.nan_to_num(np.asarray(res.evr, dtype=float))
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.bar(range(1, len(evr) + 1), evr, alpha=0.6)
        ax2 = ax.twinx()
        ax2.plot(range(1, len(evr) + 1), np.cumsum(evr), "r-o", markersize=3)
        ax2.axhline(PCA_VARIANCE_THRESHOLD, color="grey", ls="--", lw=0.8)
        ax2.set_ylim(0, 1.05)
        ax.set_xlabel("Principal component")
        ax.set_ylabel("Explained variance ratio")
        ax.set_title(f"PCA: {info['pca']['n_components']} components kept")
        fig.tight_layout()
        fig.savefig(out_dir / "pca_scree.png", dpi=150)
        plt.close(fig)

    sweep, scores = info.get("sweep"), info.get("scores")
    if sweep and scores and len(scores) > 1:
        keys = list(scores)
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.plot([float(k) for k in keys], [scores[k]["composite_score"] for k in keys], "o-")
        ax.axvline(float(info["params"][sweep["parameter"]]), color="red", ls="--", alpha=0.7)
        ax.set_xlabel(sweep["parameter"])
        ax.set_ylabel("composite score")
        ax.set_title("Parameter selection")
        fig.tight_layout()
        fig.savefig(out_dir / "metric_selection.png", dpi=150)
        plt.close(fig)


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def _read_binary_names(path: Path) -> Dict[str, str]:
    """{sha256: binary_name} from a JSON file: that mapping itself, or a
    manifest (``binaries`` list with sha256 + binary_name)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("binaries"), list):
        return {b["sha256"].lower(): b["binary_name"] for b in data["binaries"]
                if b.get("sha256") and b.get("binary_name")}
    if isinstance(data, dict):
        return {str(k).lower(): str(v) for k, v in data.items()}
    raise ValueError(f"{path}: expected a {{sha256: binary_name}} object or a manifest")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="MAPTER dimensionality reduction: SAFE embeddings (<sha256>.pkl) -> 2-D map "
                    "(x, y, binary_name, offset, name, size, sha256).")
    ap.add_argument("--embeddings-dir", type=Path, required=True,
                    help="directory with one <sha256>.pkl per binary (offset, embeddings, name, size)")
    ap.add_argument("--binary-names", type=Path, default=None,
                    help="JSON {sha256: binary_name} (or a manifest); default: sha256 prefixes "
                         "from assign_binary_names")
    ap.add_argument("--method", choices=METHODS, default="tsne",
                    help="tsne (default), umap (needs umap-learn), pca, fixed (original PCA40 + t-SNE recipe)")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--out", type=Path, default=None, help="output pickle (default: reduced_raw.pkl in the CWD)")
    ap.add_argument("--backend", choices=["auto", "cpu"], default="auto",
                    help="auto = cuML when importable and a GPU exists, else CPU")
    ap.add_argument("--no-rescale", action="store_true", help="keep the raw coordinates")
    ap.add_argument("--plots", action="store_true", help="also write PNG plots (needs matplotlib)")
    ap.add_argument("--plots-dir", type=Path, default=None, help="where the plots go (default: <out>.plots)")
    ap.add_argument("--pca-model", type=Path, default=None, help="save the PCA model (.npz)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    out = args.out or Path("reduced_raw.pkl")
    names = _read_binary_names(args.binary_names) if args.binary_names else None
    plots_dir = (args.plots_dir or out.with_suffix(".plots")) if args.plots or args.plots_dir else None
    try:
        df = reduce_embeddings(args.embeddings_dir, names, method=args.method, seed=args.seed,
                               out_pkl=out, backend=args.backend, rescale=not args.no_rescale,
                               plots_dir=plots_dir, pca_model_path=args.pca_model)
    except ValueError as exc:
        logger.error(str(exc))
        return 1
    info = df.attrs["mapter_reduce"]
    logger.info(f"done: {len(df)} functions, {info['n_binaries']} binaries, method "
                f"{info['method_used']}, params {info.get('params')}, {info['elapsed_s']}s -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
