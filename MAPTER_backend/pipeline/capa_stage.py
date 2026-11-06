"""
CAPA stage of the MAPTER pipeline.

For every binary of the manifest::

    capa <binary> --json  ->  <work>/capa_raw/<sha256>.json   (raw capa report, atomic)
                          ->  <work>/capa/<sha256>.json       (simplified, what the app reads)

``capa`` is optional: when it cannot be found the stage is skipped with a
warning and the dataset simply has no CAPA columns. A capa failure on one
binary (unsupported file type, too few features, timeout, ...) is recorded as
a per-binary failure and never aborts the run.

``merge_capa_columns`` (used by the merge stage) joins the simplified reports
onto the reduced function table with the semantics of the app's
``malware_data_loader.CapaLoader``.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

# capa_simplifier / capa_data_loader live next to the pipeline package
_BACKEND_DIR = str(Path(__file__).resolve().parent.parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from pipeline.common import (  # noqa: E402
    StopFlag, Status, WorkDir, find_tool, is_done, tool_env,
)

logger = logging.getLogger("mapter.pipeline.capa")

STAGE = "capa"

# capa's own exit codes (capa/main.py). The first group means "this binary
# cannot be analysed", which is expected for shellcode, odd formats, etc.
CAPA_EXIT_REASONS = {
    10: "rules not found (capa needs its rules: use the standalone release)",
    11: "input file not found",
    12: "invalid rule",
    13: "corrupt input file",
    14: "file limitation (too few features / packed, capa refuses to analyse it)",
    15: "invalid signatures",
    16: "unsupported file type",
    17: "unsupported file architecture",
    18: "unsupported file OS",
    19: "unsupported IDA version",
}

CAPA_COLUMNS = ['rule_name', 'tactic', 'technique', 'subtechnique', 'attack_id',
                'objective', 'behavior', 'method', 'mbc_id', 'library_name']


# --------------------------------------------------------------------------- running capa
def _kill_tree(proc: "subprocess.Popen") -> None:
    """Kill capa and its children (the PyInstaller bootloader forks a child)."""
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        pass


def _run_capa(capa: str, binary: str, out_json: Path, timeout: int, stop: StopFlag,
              env: Dict[str, str]) -> str:
    """Run ``capa <binary> --json`` writing stdout to `out_json`.

    Returns 'ok', 'cancelled' or a failure reason."""
    kwargs = {"start_new_session": True} if os.name == "posix" else {}
    with open(out_json, "wb") as fh:
        try:
            proc = subprocess.Popen([capa, binary, "--json"], stdout=fh, stderr=subprocess.PIPE,
                                    stdin=subprocess.DEVNULL, env=env, **kwargs)
        except OSError as exc:
            return f"could not start capa: {exc}"
        stderr = b""
        deadline = time.monotonic() + timeout
        while True:
            try:
                _, stderr = proc.communicate(timeout=1.0)
                break
            except subprocess.TimeoutExpired:
                if stop.is_set():
                    _kill_tree(proc)
                    return "cancelled"
                if time.monotonic() >= deadline:
                    _kill_tree(proc)
                    return f"timeout after {timeout}s"
    rc = proc.returncode
    if rc == 0:
        return "ok"
    tail = stderr.decode("utf-8", "replace").strip().splitlines()
    detail = tail[-1][:200] if tail else ""
    reason = CAPA_EXIT_REASONS.get(rc, "capa failed")
    return f"capa exit {rc}: {reason}" + (f" ({detail})" if detail and rc not in CAPA_EXIT_REASONS else "")


def _process_one(work: WorkDir, sha256: str, path: str, capa: str, timeout: int,
                 stop: StopFlag, env: Dict[str, str], force: bool) -> str:
    """Raw + simplified report of one binary (resumable). Returns 'ok' or a reason."""
    import capa_simplifier

    simple = work.capa / f"{sha256}.json"
    raw = work.capa_raw / f"{sha256}.json"
    if not force and is_done(simple):
        return "ok"

    if force or not is_done(raw):
        fd, tmp = tempfile.mkstemp(dir=work.capa_raw, prefix=f"{sha256}.", suffix=".part")
        os.close(fd)
        tmp_path = Path(tmp)
        try:
            result = _run_capa(capa, path, tmp_path, timeout, stop, env)
            if result != "ok":
                return result
            # validates that this is a capa report and writes the simplified one
            try:
                capa_simplifier.simplify_capa_file(tmp_path, simple)
            except Exception as exc:
                logger.debug(f"capa output of {sha256} rejected: {exc}")
                return "capa output is not a valid JSON report"
            os.chmod(tmp_path, 0o666 & ~capa_simplifier._UMASK)  # mkstemp creates 0600
            os.replace(tmp_path, raw)
            return "ok"
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
    try:
        capa_simplifier.simplify_capa_file(raw, simple)
    except Exception as exc:
        logger.debug(f"stored capa report of {sha256} rejected: {exc}")
        return "stored capa report is not valid (delete capa_raw/<sha256>.json to re-run)"
    return "ok"


def run(work: WorkDir, binaries: List[dict], status: Status, stop: StopFlag,
        capa_path: Optional[str] = None, timeout: int = 3600, workers: int = 4,
        force: bool = False) -> Dict[str, str]:
    """Run capa on every binary and simplify the reports.

    Args:
        work: work folder (``capa_raw/`` and ``capa/`` are written).
        binaries: manifest entries (``sha256``, ``path``).
        capa_path: capa executable; default is looked up (MAPTER_CAPA, PATH,
            the MAPTER tools dir, usual install dirs).
        timeout: seconds per binary.
        workers: binaries analysed in parallel (capa is memory hungry).
        force: re-run capa even when outputs exist.

    Returns:
        {sha256: 'ok' | failure reason}; ``{}`` when capa is not available
        (stage skipped). Binaries not reached because of a cancel are absent.
    """
    capa = find_tool(["capa", "capa.exe"], explicit=capa_path, env_var="MAPTER_CAPA")
    if capa is None:
        logger.warning("capa not found: CAPA stage skipped (install it with "
                       "tools/install_tools.py capa or pass --capa)")
        status.stage(STAGE, total=0, message="capa not found, skipped")
        return {}

    items: Dict[str, str] = {}
    for b in binaries:
        sha = str(b["sha256"]).lower()
        items.setdefault(sha, b["path"])
    work.create()
    status.stage(STAGE, total=len(items), message=f"capa ({capa})")
    env = tool_env(capa)
    results: Dict[str, str] = {}
    lock = threading.Lock()
    workers = max(1, min(int(workers), len(items) or 1))

    def task(sha: str) -> str:
        if stop.is_set():
            return "cancelled"
        status.progress(current=sha[:12])
        return _process_one(work, sha, items[sha], capa, timeout, stop, env, force)

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="capa") as pool:
        futures = {pool.submit(task, sha): sha for sha in items}
        for fut in as_completed(futures):
            sha = futures[fut]
            try:
                reason = fut.result()
            except Exception as exc:  # never let one binary kill the stage
                logger.exception(f"capa: unexpected error on {sha}")
                reason = f"unexpected error: {exc}"
            if reason == "cancelled":
                continue
            with lock:
                results[sha] = reason
            if reason != "ok":
                status.failure(STAGE, sha, reason)
            status.progress(advance=1)

    n_ok = sum(1 for r in results.values() if r == "ok")
    logger.info(f"capa: {n_ok}/{len(items)} binaries analysed, "
                f"{len(results) - n_ok} failed, {len(items) - len(results)} not run (cancelled)")
    return results


# --------------------------------------------------------------------------- merge
def merge_capa_columns(reduced_df, capa_dir, binary_names: Dict[str, str],
                       use_intervals: bool = True, legacy: bool = False):
    """Add the CAPA columns to a reduced function table.

    Args:
        reduced_df: DataFrame with ``binary_name`` and ``offset`` ('0x..' lowercase
            hex, unpadded); ``size`` (bytes) enables interval attribution.
        capa_dir: folder of simplified reports ``<sha256>.json``.
        binary_names: {sha256: binary_name} of this run.
        use_intervals: a CAPA address that does not start a known function is
            attributed to the function whose ``[offset, offset+size)`` contains it.
            Library functions always need an exact start address.
        legacy: bug-compatible with the app's ``CapaLoader`` (no interval
            attribution, string-key lookup bug).

    Returns:
        A new DataFrame with columns rule_name, tactic, technique,
        subtechnique, attack_id, objective, behavior, method, mbc_id and
        library_name (several values joined with '; '; NaN where CAPA has
        nothing). Existing CAPA columns are replaced.
    """
    import numpy as np
    from capa_data_loader import CapaLoader

    missing = {"binary_name", "offset"} - set(reduced_df.columns)
    if missing:
        raise ValueError(f"reduced table lacks columns: {sorted(missing)}")

    df = reduced_df.drop(columns=[c for c in CAPA_COLUMNS if c in reduced_df.columns])
    capa_dir = str(capa_dir)
    shas = [s for s in binary_names if os.path.isfile(os.path.join(capa_dir, f"{s}.json"))]

    out = df.copy()
    if shas:
        loader = CapaLoader(capa_dir, legacy=legacy)
        frames = loader.load_capa_data(shas)
        out = loader.merge_capa_with_df(df, frames, binary_names=binary_names,
                                        use_intervals=use_intervals and not legacy)
    else:
        logger.warning(f"merge_capa_columns: no CAPA reports in {capa_dir} for this run")

    for col in CAPA_COLUMNS:
        if col not in out.columns:
            out[col] = np.nan
            out[col] = out[col].astype(object)
    out = out[[c for c in out.columns if c not in CAPA_COLUMNS] + CAPA_COLUMNS]
    logger.info(f"CAPA columns merged: {int(out['rule_name'].notna().sum())}/{len(out)} functions "
                f"with rules, {int(out['library_name'].notna().sum())} with a library name "
                f"({len(shas)}/{len(binary_names)} binaries have a report)")
    return out
