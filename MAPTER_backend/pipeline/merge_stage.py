"""
Merge stage of the MAPTER pipeline: builds the final MAPTER data folder.

Inputs (all inside the work folder, see ``pipeline.common``):

* ``reduced_raw.pkl``   x, y, binary_name, offset, name, size, sha256
* ``capa/<sha256>.json`` simplified CAPA reports (optional)
* ``avclass.pkl``        binary_name, label, sha256, ... (optional)

Output (the data folder the Dash app loads)::

    reduced.pkl    one enriched DataFrame: x, y, binary_name, offset, name, size,
                   sha256 [+ rule_name, tactic, technique, subtechnique, attack_id,
                   objective, behavior, method, mbc_id, library_name] [+ avclass_label]
    dataset.json   manifest the app reads (id, name, thresholds, ...)
    binaries.json  {binary_name: {sha256, program_name, domain_path, path}}
    capa/          simplified CAPA JSONs (provenance)
    avclass.pkl    AVClass table (provenance)

The CAPA columns follow ``malware_data_loader.CapaLoader.merge_capa_with_df``:
a left join on ``(binary_name, offset)`` where several values of one function are
joined with ``'; '`` (sorted, unique). When there is no CAPA / AVClass data the
corresponding columns are absent (not empty).
"""
from __future__ import annotations

import importlib.util
import json
import logging
import math
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd

from .common import WorkDir, atomic_to_pickle, atomic_write_json

logger = logging.getLogger("mapter.pipeline.merge")

CAPA_FUNCTION_COLUMNS = ["rule_name", "tactic", "technique", "subtechnique", "attack_id",
                         "objective", "behavior", "method", "mbc_id"]
CAPA_LIBRARY_COLUMNS = ["library_name"]
CAPA_COLUMNS = CAPA_FUNCTION_COLUMNS + CAPA_LIBRARY_COLUMNS
BASE_COLUMNS = ["x", "y", "binary_name", "offset", "name", "size", "sha256"]

DEFAULT_FUNCTION_THRESHOLD = 5.0
DEFAULT_BINARY_THRESHOLD = 0.2
DEFAULT_DISTANCE_THRESHOLD = 0.75
DEFAULT_AVCLASS_THRESHOLD = 0.9
LOW_CAPA_COVERAGE = 0.10

_ATTACK_FIELDS = {"tactic": "tactic_attck", "technique": "technique_attck",
                  "subtechnique": "subtechnique_attck", "attack_id": "attck_id"}
_MBC_FIELDS = {"objective": "objective_mbc", "behavior": "behavior_mbc",
               "method": "method_mbc", "mbc_id": "mbc_id"}


# --------------------------------------------------------------------------- CAPA
def _to_offset(addr) -> Optional[str]:
    """Function address from a simplified CAPA report -> '0x..' (hex of the int VA)."""
    if addr is None or isinstance(addr, bool):
        return None
    try:
        return hex(int(addr))
    except (TypeError, ValueError):
        return str(addr) if addr else None


def _flatten(items) -> list:
    out: list = []
    for it in items or []:
        if isinstance(it, (list, tuple)):
            out.extend(_flatten(it))
        else:
            out.append(it)
    return out


def _rule_functions(rule: dict, function_map: dict) -> list:
    """Function addresses of one rule. Uses ``associated_funcs`` when it covers
    every associated address, otherwise maps the (block/instruction) addresses to
    their function through ``analysis.file_functions``."""
    funcs = _flatten(rule.get("associated_funcs"))
    addrs = _flatten(rule.get("associated_addresses"))
    if len(funcs) >= len(addrs):
        return funcs
    return [function_map.get(str(a), function_map.get(a, a)) for a in addrs]


def parse_capa_report(path: Path) -> Tuple[Dict[str, Dict[str, set]], Dict[str, set]]:
    """Read one simplified CAPA JSON.

    Returns ``(functions, libraries)``: ``functions[offset][column]`` is the set
    of values of the rule columns for that function, ``libraries[offset]`` the
    set of library names."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    analysis = data.get("analysis") or {}
    function_map = analysis.get("file_functions") or {}
    functions: Dict[str, Dict[str, set]] = {}

    for rule_name, rule in (data.get("rules") or {}).items():
        attack = rule.get("rule_attack") or {}
        mbc = rule.get("rule_mbc") or {}
        values = {"rule_name": rule_name}
        values.update({col: attack.get(src) for col, src in _ATTACK_FIELDS.items()})
        values.update({col: mbc.get(src) for col, src in _MBC_FIELDS.items()})
        for addr in _rule_functions(rule, function_map):
            offset = _to_offset(addr)
            if offset is None:
                continue
            slot = functions.setdefault(offset, {})
            for col, val in values.items():
                if val is not None and not (isinstance(val, float) and math.isnan(val)):
                    slot.setdefault(col, set()).add(str(val))

    libraries: Dict[str, set] = {}
    for addr, lib in (analysis.get("library_functions") or {}).items():
        offset = _to_offset(addr)
        if offset is not None:
            libraries.setdefault(offset, set()).add("Unknown library" if lib == "?" else str(lib))
    return functions, libraries


def _join(values: Optional[set]) -> Optional[str]:
    return "; ".join(sorted(values)) if values else None


def add_capa_columns(df: pd.DataFrame, capa_dir: Path, sha_to_name: Dict[str, str]) -> Tuple[pd.DataFrame, dict]:
    """Left-join the simplified CAPA reports in `capa_dir` onto `df` on
    (binary_name, offset). Returns ``(df, stats)``; `df` is returned unchanged
    (no CAPA columns) when there is no readable report for any binary of `df`."""
    present = set(df["binary_name"].unique())
    rows: Dict[Tuple[str, str], Dict[str, Optional[str]]] = {}
    parsed = 0
    for sha, name in sha_to_name.items():
        f = capa_dir / f"{sha}.json"
        if name not in present or not f.is_file() or f.stat().st_size == 0:
            continue
        try:
            functions, libraries = parse_capa_report(f)
        except Exception as exc:  # noqa: BLE001 - a bad report must not stop the merge
            logger.warning(f"Ignoring unreadable CAPA report {f.name}: {exc}")
            continue
        parsed += 1
        for offset, cols in functions.items():
            rows.setdefault((name, offset), {}).update({c: _join(v) for c, v in cols.items()})
        for offset, libs in libraries.items():
            rows.setdefault((name, offset), {})["library_name"] = _join(libs)

    if parsed == 0:
        return df, {"binaries": 0}

    keys = list(zip(df["binary_name"], df["offset"]))
    out = df.copy()
    for col in CAPA_COLUMNS:
        out[col] = pd.Series([rows.get(k, {}).get(col) for k in keys], index=df.index, dtype=object)

    stats = {"binaries": parsed, "functions": len(df),
             "rule_rows": int(out["rule_name"].notna().sum()),
             "library_rows": int(out["library_name"].notna().sum())}
    logger.info(f"CAPA: {parsed} reports; {stats['rule_rows']}/{len(df)} functions with rules, "
                f"{stats['library_rows']}/{len(df)} library functions")
    for name, grp in out.groupby("binary_name"):
        matched = float(grp[["rule_name", "library_name"]].notna().any(axis=1).mean())
        if matched < LOW_CAPA_COVERAGE:
            logger.warning(f"CAPA coverage for binary {name} is {matched:.0%} "
                           f"(usually .NET, shellcode or different function discovery)")
    return out, stats


# --------------------------------------------------------------------------- AVClass
def add_avclass_label(df: pd.DataFrame, avclass_path: Path, sha_to_name: Dict[str, str]) -> pd.DataFrame:
    """Add ``avclass_label`` from the AVClass table; absent when there is none.
    Rows are matched by sha256 when the table has it (robust to the binary_name
    length of the run), else by binary_name."""
    if not avclass_path.is_file() or avclass_path.stat().st_size == 0:
        return df
    try:
        av = pd.read_pickle(avclass_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Ignoring unreadable {avclass_path.name}: {exc}")
        return df
    if "label" not in av.columns:
        logger.warning(f"{avclass_path.name} has no 'label' column; skipping avclass_label")
        return df

    if "sha256" in av.columns:
        names = av["sha256"].astype(str).str.lower().map(sha_to_name)
    elif "binary_name" in av.columns:
        names = av["binary_name"].astype(str)
    else:
        logger.warning(f"{avclass_path.name} has neither sha256 nor binary_name; skipping avclass_label")
        return df
    labels = {n: l for n, l in zip(names, av["label"]) if isinstance(n, str) and pd.notna(l)}
    present = set(df["binary_name"].unique())
    if not (set(labels) & present):
        logger.warning("AVClass table matches none of the binaries; skipping avclass_label")
        return df
    out = df.copy()
    out["avclass_label"] = out["binary_name"].map(labels).astype(object)
    logger.info(f"AVClass: labels for {len(set(labels) & present)}/{len(present)} binaries")
    return out


# --------------------------------------------------------------------------- dataset.json
def _load_recommend_delta(app_dir: Optional[Path]):
    """Import the app's recommend_delta.py by path (no sys.path side effects)."""
    if app_dir is None:
        return None
    f = Path(app_dir) / "recommend_delta.py"
    if not f.is_file():
        return None
    spec = importlib.util.spec_from_file_location("mapter_recommend_delta", f)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def default_function_threshold(df: pd.DataFrame, app_dir: Optional[Path]) -> float:
    """The p40 candidate of recommend_delta.recommend() for this map, else 5.0."""
    try:
        mod = _load_recommend_delta(app_dir)
        if mod is None or df["binary_name"].nunique() < 2:
            return DEFAULT_FUNCTION_THRESHOLD
        coords = df[["x", "y"]].to_numpy(dtype=float)
        rec = mod.recommend(coords, df["binary_name"].to_numpy(), n_boot=0)
        cands = rec.get("candidates") or []
        if not cands:
            return DEFAULT_FUNCTION_THRESHOLD
        best = min(cands, key=lambda c: abs(c["percentile"] - 40))
        delta = round(float(best["delta"]), 3)
        if not math.isfinite(delta) or delta <= 0:
            return DEFAULT_FUNCTION_THRESHOLD
        logger.info(f"default_function_threshold = {delta} (p{best['percentile']} of recommend_delta)")
        return delta
    except Exception as exc:  # noqa: BLE001 - optional nicety, never fatal
        logger.warning(f"recommend_delta unavailable ({exc}); using {DEFAULT_FUNCTION_THRESHOLD}")
        return DEFAULT_FUNCTION_THRESHOLD


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_.") or "mapter"


# --------------------------------------------------------------------------- stage
def run(work: WorkDir, manifest: dict, binary_names: Dict[str, str], name: str, method: str,
        app_dir: Optional[Path] = None, out_dir: Optional[Path] = None) -> Path:
    """Build the data folder and return its path (`out_dir`, default
    ``work.data_folder``). Raises FileNotFoundError when ``reduced_raw.pkl`` is
    missing."""
    out = Path(out_dir) if out_dir else work.data_folder
    if out.resolve() == work.root.resolve():
        raise ValueError("the data folder must not be the work folder itself (use a subfolder)")
    if not work.reduced_raw.is_file():
        raise FileNotFoundError(f"reduce stage output not found: {work.reduced_raw}")
    out.mkdir(parents=True, exist_ok=True)

    df = pd.read_pickle(work.reduced_raw)
    # What the reducer actually ran (it may have fallen back from the request).
    used = (df.attrs.get("mapter_reduce") or {}).get("method_used")
    if used and used != method:
        logger.info(f"method '{method}' was run as '{used}'")
        method = used
    missing = [c for c in BASE_COLUMNS[:6] if c not in df.columns]
    if missing:
        raise ValueError(f"{work.reduced_raw} is missing columns {missing}")
    name_to_sha = {v: k for k, v in binary_names.items()}
    if "sha256" not in df.columns:
        df["sha256"] = df["binary_name"].map(name_to_sha)
    df = df[BASE_COLUMNS].copy()
    df["x"] = df["x"].astype(np.float32)
    df["y"] = df["y"].astype(np.float32)
    df["size"] = pd.to_numeric(df["size"], errors="coerce")
    df = df.reset_index(drop=True)

    on_map = set(df["binary_name"])
    sha_to_name = {s: n for s, n in binary_names.items() if n in on_map}

    df, capa_stats = add_capa_columns(df, work.capa, sha_to_name)
    df = add_avclass_label(df, work.avclass, sha_to_name)
    atomic_to_pickle(df, out / "reduced.pkl")

    # ---- provenance: capa/, avclass.pkl
    has_capa = "rule_name" in df.columns
    capa_out = out / "capa"
    if capa_out.exists():
        shutil.rmtree(capa_out)
    if has_capa:
        capa_out.mkdir(parents=True)
        for sha in sha_to_name:
            src = work.capa / f"{sha}.json"
            if src.is_file() and src.stat().st_size > 0:
                shutil.copy2(src, capa_out / src.name)
    has_avclass = "avclass_label" in df.columns
    if has_avclass:
        shutil.copy2(work.avclass, out / "avclass.pkl")
    elif (out / "avclass.pkl").exists():
        (out / "avclass.pkl").unlink()

    # ---- binaries.json
    # First usable entry per sha256 (a binary imported twice yields a skipped duplicate).
    by_sha: Dict[str, dict] = {}
    for b in manifest.get("binaries", []):
        if b.get("status", "ok") == "ok":
            by_sha.setdefault(b.get("sha256"), b)
    for b in manifest.get("binaries", []):
        by_sha.setdefault(b.get("sha256"), b)
    binaries = {}
    for sha, bn in sorted(sha_to_name.items(), key=lambda kv: kv[1]):
        b = by_sha.get(sha, {})
        binaries[bn] = {"sha256": sha, "program_name": b.get("program_name"),
                        "domain_path": b.get("domain_path"), "path": b.get("path")}
    atomic_write_json(out / "binaries.json", binaries)

    # ---- dataset.json
    dataset = {
        "id": _slug(name), "name": name,
        "description": f"{name}: SAFE embeddings of {df['binary_name'].nunique()} binaries "
                       f"reduced to 2D ({method}) with MAPTER.",
        "reduced": "reduced.pkl",
        "generated_by": "mapter_pipeline",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": method,
        "n_binaries": int(df["binary_name"].nunique()),
        "n_functions": int(len(df)),
        "default_function_threshold": default_function_threshold(df, app_dir),
        "default_binary_threshold": DEFAULT_BINARY_THRESHOLD,
        "default_distance_threshold": DEFAULT_DISTANCE_THRESHOLD,
        "avclass_threshold": DEFAULT_AVCLASS_THRESHOLD,
    }
    if has_avclass:
        dataset["avclass"] = "avclass.pkl"
    atomic_write_json(out / "dataset.json", dataset)

    logger.info(f"Data folder ready: {out} ({dataset['n_functions']} functions, "
                f"{dataset['n_binaries']} binaries, capa={has_capa}, avclass={has_avclass})")
    return out
