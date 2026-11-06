"""
SAFE embedding stage of the MAPTER pipeline.

``run`` embeds every binary of the manifest into ``<work>/embeddings/<sha256>.pkl``
(DataFrame: offset str, embeddings list[100 floats], name str, size). Each binary
runs in its own child process (``python -m pipeline.safe_stage --one ...``): radare2
analysis can hang or exhaust memory, so the child is killed (with its radare2
process group) when it exceeds the timeout, and the model is loaded per child.

Resume: an existing non-empty ``<sha256>.pkl`` is kept. Per-binary failures are
reported through ``Status.failure`` and returned as the reason string; they never
abort the stage. Only a missing radare2 or model is fatal (RuntimeError).

Cancellation: when the StopFlag is set no new binary starts; running children get
``STOP_GRACE`` seconds to finish and are then killed (their output is discarded;
the run stays resumable).
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional

from pipeline.common import Status, StopFlag, WorkDir, find_tool, is_done, tool_env

logger = logging.getLogger("mapter.pipeline.safe")

BACKEND_DIR = Path(__file__).resolve().parent.parent
STOP_GRACE = 20.0           # seconds a running child may finish after a cancel request
ERROR_MARKER = "MAPTER_SAFE_ERROR:"
OK_MARKER = "MAPTER_SAFE_OK:"
MODEL_FILES = ("SAFEtorch.pt", "word2id.json")


# --------------------------------------------------------------------------- helpers
def radare2_version(r2: str) -> Optional[str]:
    """Version string from ``radare2 -v`` (e.g. '6.2.4'), None if it cannot be run."""
    try:
        out = subprocess.run([r2, "-v"], capture_output=True, text=True, timeout=20,
                             env=tool_env(r2)).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"radare2\s+(\d+\.\d+(?:\.\d+)?)", out)
    return m.group(1) if m else None


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the child and everything it spawned (radare2)."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=30)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _failure_reason(stderr: str, returncode: int) -> str:
    for line in reversed(stderr.splitlines()):
        if line.startswith(ERROR_MARKER):
            return line[len(ERROR_MARKER):].strip()
    tail = [l for l in stderr.strip().splitlines() if l.strip()][-3:]
    detail = " | ".join(tail)[:300]
    return f"SAFE child exited with code {returncode}" + (f": {detail}" if detail else "")


def _run_child(binary: Path, out_pkl: Path, model_dir: Path, r2: Optional[str],
               timeout: int, stop: StopFlag) -> str:
    """Run ``--one`` for one binary; 'ok' or a failure reason."""
    cmd = [sys.executable, "-m", "pipeline.safe_stage", "--one", str(binary),
           "--out", str(out_pkl), "--model-dir", str(model_dir)]
    if r2:
        cmd += ["--r2", r2]
    env = tool_env(r2)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(BACKEND_DIR), env.get("PYTHONPATH")]))
    env["PYTHONUNBUFFERED"] = "1"
    kwargs = {"start_new_session": True} if os.name != "nt" else {}
    proc = subprocess.Popen(cmd, cwd=str(BACKEND_DIR), env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    deadline = time.monotonic() + timeout
    stop_deadline: Optional[float] = None
    while True:
        try:
            _, stderr = proc.communicate(timeout=1.0)
            break
        except subprocess.TimeoutExpired:
            now = time.monotonic()
            if stop.is_set() and stop_deadline is None:
                stop_deadline = now + STOP_GRACE
            if stop_deadline is not None and now > stop_deadline:
                _kill_tree(proc)
                proc.communicate()
                _discard(out_pkl)
                return "cancelled"
            if now > deadline:
                _kill_tree(proc)
                proc.communicate()
                _discard(out_pkl)
                return f"timeout after {timeout} s"
    if proc.returncode == 0 and is_done(out_pkl):
        return "ok"
    _discard(out_pkl)
    return _failure_reason(stderr or "", proc.returncode)


def _discard(out_pkl: Path) -> None:
    for p in (out_pkl, out_pkl.with_name(out_pkl.name + ".tmp")):
        try:
            p.unlink()
        except OSError:
            pass


# --------------------------------------------------------------------------- stage
def run(work: WorkDir, binaries: List[dict], status: Status, stop: StopFlag,
        model_dir: Path, r2_path: Optional[str], timeout: int = 1800,
        workers: int = 1) -> Dict[str, str]:
    """Embed `binaries` (manifest entries with sha256/path). Returns {sha256: 'ok' | reason}.

    Raises RuntimeError when radare2 or the SAFE model files are missing (nothing
    can be done), otherwise per-binary problems are only reported.
    """
    model_dir = Path(model_dir)
    missing = [f for f in MODEL_FILES if not (model_dir / f).is_file()]
    if missing:
        raise RuntimeError(f"SAFE model files missing in {model_dir}: {', '.join(missing)}")
    r2 = find_tool(["radare2", "r2"], r2_path, "MAPTER_R2")
    if r2 is None:
        raise RuntimeError("radare2 not found (install radare2 >= 6 or pass --r2 PATH)")
    version = radare2_version(r2)
    logger.info("radare2 %s at %s", version or "(version unknown)", r2)
    if version and int(version.split(".")[0]) < 6:
        logger.warning("radare2 %s is older than 6; the aflj/aoj output may differ", version)

    work.embeddings.mkdir(parents=True, exist_ok=True)
    results: Dict[str, str] = {}
    todo: List[dict] = []
    for b in binaries:
        if is_done(work.embeddings / f"{b['sha256']}.pkl"):
            results[b["sha256"]] = "ok"
        else:
            todo.append(b)
    status.stage("safe", total=len(binaries),
                 message=f"SAFE embeddings ({len(results)} already done)")
    status.progress(done=len(results))
    if not todo:
        return results

    lock = threading.Lock()

    def one(b: dict) -> None:
        sha = b["sha256"]
        label = b.get("program_name") or sha[:12]
        if stop.is_set():
            reason = "cancelled"
        else:
            status.progress(current=label)
            t0 = time.monotonic()
            try:
                reason = _run_child(Path(b["path"]), work.embeddings / f"{sha}.pkl",
                                    model_dir, r2, timeout, stop)
            except Exception as e:  # keep the stage alive on any per-binary surprise
                logger.exception("SAFE failed for %s", label)
                reason = f"{type(e).__name__}: {e}"
            logger.info("SAFE %s: %s (%.1f s)", label, reason, time.monotonic() - t0)
        with lock:
            results[sha] = reason
        if reason == "ok":
            status.progress(advance=1)
        elif reason == "cancelled":
            pass
        else:
            status.failure("safe", sha, f"{label}: {reason}")
            status.progress(advance=1)

    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        list(pool.map(one, todo))
    return results


# --------------------------------------------------------------------------- child
def _child_main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m pipeline.safe_stage",
                                 description="Embed one binary (used by the SAFE stage).")
    ap.add_argument("--one", required=True, metavar="BIN", help="binary to analyse")
    ap.add_argument("--out", required=True, metavar="PKL", help="output pickle")
    ap.add_argument("--model-dir", required=True)
    ap.add_argument("--r2", default=None)
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    try:
        import safe_main  # heavy (torch); only the child needs it
        from utils.radare_function_analyzer import RadareError
        if args.threads > 0:
            safe_main.torch.set_num_threads(args.threads)
        try:
            n = safe_main.embed_binary_to_pickle(args.one, args.out, args.model_dir, args.r2)
        except (RadareError, safe_main.NoFunctionsError, FileNotFoundError) as e:
            print(f"{ERROR_MARKER} {e}", file=sys.stderr)
            return 3
        print(f"{OK_MARKER} {n}")
        return 0
    except ImportError as e:
        print(f"{ERROR_MARKER} missing Python dependency: {e}", file=sys.stderr)
        return 4
    except Exception as e:
        logger.exception("SAFE child failed")
        print(f"{ERROR_MARKER} {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_child_main())
