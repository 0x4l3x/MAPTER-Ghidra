#!/usr/bin/env python3
"""
MAPTER generation pipeline: from a folder of binaries (or a Ghidra manifest) to a
MAPTER data folder that the Dash app loads.

Stages (all resumable; rerunning skips finished per-binary outputs):

    safe     radare2 + SAFE function embeddings   -> <work>/embeddings/<sha256>.pkl
    capa     capa --json + simplification          -> <work>/capa/<sha256>.json
    avclass  AVClass2 family labels (VT reports)   -> <work>/avclass.pkl
    reduce   2D reduction (t-SNE / UMAP / PCA)     -> <work>/reduced_raw.pkl
    merge    enriched reduced.pkl + dataset.json   -> <out> (default <work>/data_folder)

Examples::

    python mapter_pipeline.py --check
    python mapter_pipeline.py --work /tmp/w --binaries ~/samples --name MySamples
    python mapter_pipeline.py --work W --manifest W/manifest.json --out W/data_folder

Progress is written to <work>/status.json, the log to <work>/pipeline.log.
SIGTERM/SIGINT finish the current binary, then exit 2 with state 'cancelled'
(a second signal stops immediately). Exit codes: 0 ok, 1 failure, 2 cancelled.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from pipeline.common import (STAGES, Status, StopFlag, WorkDir, assign_binary_names,  # noqa: E402
                             atomic_write_json, find_tool, is_done, ok_binaries,
                             setup_logging, sha256_file, tool_env)

logger = logging.getLogger("mapter.pipeline")

MIN_R2_VERSION = (6, 0)
EXIT_OK, EXIT_FAILED, EXIT_CANCELLED = 0, 1, 2

# import name -> (distribution name, required)
PACKAGES = {
    "torch": ("torch", True), "r2pipe": ("r2pipe", True), "pandas": ("pandas", True),
    "numpy": ("numpy", True), "sklearn": ("scikit-learn", True),
    "avclass": ("avclass-malicialab", False), "umap": ("umap-learn", False),
}
MODEL_FILES = ("SAFEtorch.pt", "word2id.json")


class PipelineError(Exception):
    """Fatal, user-facing pipeline failure (state 'failed', exit 1)."""


class Cancelled(Exception):
    """The run was cancelled by a signal (state 'cancelled', exit 2)."""


# --------------------------------------------------------------------------- tools
def _parse_version(text: str, prefix: Optional[str] = None) -> Optional[str]:
    pat = (re.escape(prefix) + r"\s+v?" if prefix else r"\bv?") + r"(\d+\.\d+(?:\.\d+)*)"
    m = re.search(pat, text)
    return m.group(1) if m else None


def _tool_version(path: str, args: List[str], prefix: Optional[str] = None) -> Optional[str]:
    try:
        res = subprocess.run([path, *args], capture_output=True, text=True, timeout=30,
                             env=tool_env(path), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug(f"{path} {' '.join(args)} failed: {exc}")
        return None
    return _parse_version((res.stdout or "") + "\n" + (res.stderr or ""), prefix)


def radare2_info(explicit: Optional[str]) -> Optional[dict]:
    path = find_tool(["radare2", "r2"], explicit, "MAPTER_R2")
    if not path:
        return None
    return {"path": path, "version": _tool_version(path, ["-v"], "radare2")}


def capa_info(explicit: Optional[str]) -> Optional[dict]:
    path = find_tool(["capa", "capa.exe"], explicit, "MAPTER_CAPA")
    if not path:
        return None
    return {"path": path, "version": _tool_version(path, ["--version"])}


def _version_tuple(v: Optional[str]) -> tuple:
    return tuple(int(p) for p in re.findall(r"\d+", v or "")[:3])


def _r2_too_old(info: Optional[dict]) -> bool:
    return bool(info and info.get("version") and _version_tuple(info["version"]) < MIN_R2_VERSION)


def check_prerequisites(model_dir: Path, r2: Optional[str], capa: Optional[str]) -> dict:
    """The --check report: packages, radare2, capa, model files and problems."""
    packages: Dict[str, Optional[str]] = {}
    problems: List[str] = []
    warnings: List[str] = []
    import importlib
    import importlib.metadata as md
    for mod, (dist, required) in PACKAGES.items():
        try:
            # libraries may chatter on stdout; the report must be the only JSON there
            with contextlib.redirect_stdout(io.StringIO()):
                m = importlib.import_module(mod)
            try:
                version = md.version(dist)
            except md.PackageNotFoundError:
                version = getattr(m, "__version__", "unknown")
            packages[mod] = str(version)
        except Exception as exc:  # noqa: BLE001 - ImportError and broken installs alike
            packages[mod] = None
            msg = f"Python package '{dist}' is not usable ({type(exc).__name__}: {exc}); " \
                  f"install it with: {sys.executable} -m pip install {dist}"
            (problems if required else warnings).append(msg)

    r2_info = radare2_info(r2)
    if r2_info is None:
        problems.append("radare2 not found (need >= 6.0). Install it (brew install radare2, "
                        "or python tools/install_tools.py radare2) or pass --r2 PATH")
    elif r2_info["version"] is None:
        problems.append(f"could not read the radare2 version from {r2_info['path']} (need >= 6.0)")
    elif _r2_too_old(r2_info):
        problems.append(f"radare2 {r2_info['version']} at {r2_info['path']} is too old (need >= 6.0)")

    capa_i = capa_info(capa)
    if capa_i is None:
        warnings.append("capa not found: the CAPA stage will be skipped "
                        "(python tools/install_tools.py capa installs it)")

    missing_model = [f for f in MODEL_FILES if not is_done(model_dir / f)]
    model = {"dir": str(model_dir), "ok": not missing_model}
    if missing_model:
        problems.append(f"model files missing in {model_dir}: {', '.join(missing_model)}")

    return {"ok": not problems, "python": sys.version.split()[0], "python_executable": sys.executable,
            "packages": packages, "radare2": r2_info, "capa": capa_i, "model": model,
            "problems": problems, "warnings": warnings}


# --------------------------------------------------------------------------- lock
def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(k32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    # guard against PID reuse: the holder must still look like a python/pipeline process
    try:
        res = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=5)
        if res.returncode != 0 and not res.stdout.strip():
            return False
        cmd = res.stdout.lower()
        return "mapter_pipeline" in cmd or "python" in cmd
    except (OSError, subprocess.SubprocessError):
        return True


def acquire_lock(path: Path) -> None:
    """Create <work>/pipeline.lock holding our pid; PipelineError if another live
    pipeline process holds it. A lock of a dead pid is stale and replaced."""
    for _ in range(3):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                holder = int(path.read_text().strip() or 0)
            except (OSError, ValueError):
                holder = 0
            if holder and holder != os.getpid() and _pid_alive(holder):
                raise PipelineError(f"another pipeline (pid {holder}) is running in this work "
                                    f"folder (lock {path})")
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            continue
        with os.fdopen(fd, "w") as fh:
            fh.write(str(os.getpid()))
        return
    raise PipelineError(f"could not acquire lock {path}")


def release_lock(path: Path) -> None:
    try:
        if path.read_text().strip() == str(os.getpid()):
            path.unlink()
    except OSError:
        pass


# --------------------------------------------------------------------------- inputs
def _file_format(path: Path) -> str:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return ""
    if head[:2] == b"MZ":
        return "PE"
    if head == b"\x7fELF":
        return "ELF"
    if head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    return ""


def _place(src: Path, dest: Path) -> None:
    """Hardlink (else copy) `src` to `dest` unless a file of the same size is there."""
    if dest.exists() and dest.stat().st_size == src.stat().st_size:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    try:
        os.link(src, tmp)
    except OSError:
        shutil.copy2(src, tmp)
    os.replace(tmp, dest)


def scan_folder(folder: Path, work: WorkDir, status: Status, stop: StopFlag) -> dict:
    """Hash every regular file of `folder` (recursively), place it as
    <work>/binaries/<sha256> and return the manifest (source 'folder')."""
    folder = folder.resolve()
    if not folder.is_dir():
        raise PipelineError(f"--binaries is not a folder: {folder}")
    work_root = work.root.resolve()
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(folder):
        dp = Path(dirpath).resolve()
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and (dp / d).resolve() != work_root)
        for fn in sorted(filenames):
            p = dp / fn
            if fn.startswith(".") or p.is_symlink() or not p.is_file():
                continue
            files.append(p)

    status.stage("prepare", total=len(files), message=f"Hashing {len(files)} files")
    entries: List[dict] = []
    duplicates: List[dict] = []
    seen: Dict[str, dict] = {}
    for i, p in enumerate(files, 1):
        if stop.is_set():
            raise Cancelled()
        rel = p.relative_to(folder).as_posix()
        status.progress(done=i - 1, current=rel)
        try:
            if p.stat().st_size == 0:
                logger.warning(f"Skipping empty file {rel}")
                continue
            sha = sha256_file(p)
            if sha in seen:
                logger.warning(f"Skipping duplicate {rel} (same content as {seen[sha]['program_name']})")
                duplicates.append({"sha256": sha, "program_name": p.name, "domain_path": "/" + rel})
                continue
            dest = work.binaries / sha
            _place(p, dest)
        except OSError as exc:
            logger.warning(f"Skipping {rel}: {exc}")
            continue
        entry = {"sha256": sha, "path": str(dest), "program_name": p.name, "domain_path": "/" + rel,
                 "format": _file_format(p), "size": p.stat().st_size, "source_path": str(p),
                 "status": "ok"}
        seen[sha] = entry
        entries.append(entry)
    status.progress(done=len(files))
    return {"source": "folder", "project": folder.name, "binaries": entries, "duplicates": duplicates}


def load_input_manifest(path: Path, work: WorkDir) -> dict:
    """Read a manifest (written by Ghidra), normalise it and make it the work
    folder's manifest.json."""
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PipelineError(f"cannot read manifest {path}: {exc}") from exc
    for b in manifest.get("binaries", []):
        if b.get("sha256"):
            b["sha256"] = b["sha256"].lower()
        if b.get("path") and not os.path.isabs(b["path"]):
            b["path"] = str(work.root / b["path"])
        if b.get("status", "ok") == "ok" and (not b.get("sha256") or not b.get("path")
                                                or not os.path.exists(b["path"])):
            b["status"] = "missing"
            b.setdefault("reason", "file not found")
    return manifest


# --------------------------------------------------------------------------- stages
def _log_results(stage: str, results, status: Status) -> None:
    if not isinstance(results, dict):
        return
    failed = {k: v for k, v in results.items()
              if v != "ok" and v is not True and v != "cancelled"}
    logger.info(f"[{stage}] {len(results) - len(failed)} ok, {len(failed)} not ok")
    known = status.data.get("failures", {}).get(stage, {})
    for sha, reason in failed.items():
        if sha not in known:
            status.failure(stage, str(sha), str(reason))


def _check_stop(stop: StopFlag) -> None:
    if stop.is_set():
        raise Cancelled()


def stage_safe(ctx: dict) -> None:
    work, status, stop, args = ctx["work"], ctx["status"], ctx["stop"], ctx["args"]
    r2 = radare2_info(args.r2)
    if r2 is None:
        raise PipelineError("radare2 not found: install radare2 >= 6.0 or pass --r2 PATH")
    if _r2_too_old(r2):
        logger.warning(f"radare2 {r2['version']} is older than 6.0; function listing may be wrong")
    try:
        from pipeline import safe_stage
    except ImportError as exc:
        raise PipelineError(f"SAFE stage unavailable ({exc}); install requirements-pipeline.txt") from exc
    status.stage("safe", total=len(ctx["binaries"]), message="SAFE embeddings")
    res = safe_stage.run(work, ctx["binaries"], status, stop, Path(args.model_dir), r2["path"],
                         timeout=args.r2_timeout, workers=args.workers)
    _log_results("safe", res, status)


def stage_capa(ctx: dict) -> None:
    work, status, stop, args = ctx["work"], ctx["status"], ctx["stop"], ctx["args"]
    capa = capa_info(args.capa)
    if capa is None:
        logger.warning("capa not found: CAPA stage skipped (no CAPA columns in the result)")
        return
    try:
        from pipeline import capa_stage
    except ImportError as exc:
        logger.warning(f"CAPA stage unavailable ({exc}); skipped")
        return
    status.stage("capa", total=len(ctx["binaries"]), message="CAPA analysis")
    res = capa_stage.run(work, ctx["binaries"], status, stop, capa["path"],
                         timeout=args.capa_timeout, workers=args.workers)
    _log_results("capa", res, status)


def stage_avclass(ctx: dict) -> None:
    work, status, stop, args = ctx["work"], ctx["status"], ctx["stop"], ctx["args"]
    fetch = args.vt_fetch
    # Read once and drop it from the environment so radare2/capa/SAFE children never see it.
    api_key = os.environ.pop("VT_API_KEY", None) or None
    if fetch and not api_key:
        logger.warning("--vt-fetch given but VT_API_KEY is not set: not fetching from VirusTotal")
        fetch = False
    try:
        from pipeline import avclass_stage
    except ImportError as exc:
        logger.warning(f"AVClass stage unavailable ({exc}); skipped")
        return
    status.stage("avclass", total=len(ctx["binaries"]), message="AVClass labels")
    try:
        out = avclass_stage.run(work, ctx["binaries"], status, stop, ctx["binary_names"],
                                reports_dir=Path(args.vt_reports) if args.vt_reports else None,
                                api_key=api_key, fetch=fetch)
    except Exception as exc:  # noqa: BLE001 - labels are optional
        if stop.is_set():
            raise Cancelled() from exc
        logger.warning(f"AVClass stage failed ({exc}); continuing without labels")
        return
    logger.info(f"[avclass] {'labels written to ' + str(out) if out else 'skipped (no labels)'}")


def stage_reduce(ctx: dict) -> None:
    work, status, stop, args = ctx["work"], ctx["status"], ctx["stop"], ctx["args"]
    names = {sha: bn for sha, bn in ctx["binary_names"].items() if is_done(work.embeddings / f"{sha}.pkl")}
    if not names:
        raise PipelineError("no SAFE embeddings to reduce (the safe stage produced nothing)")
    if len(names) < len(ctx["binary_names"]):
        logger.warning(f"{len(ctx['binary_names']) - len(names)} binaries have no embeddings "
                       f"and are left out of the map")
    try:
        import mapter
    except ImportError as exc:
        raise PipelineError(f"reduction unavailable ({exc}); install requirements-pipeline.txt") from exc
    status.stage("reduce", total=len(names), message=f"Reducing to 2D ({args.method})")
    try:
        df = mapter.reduce_embeddings(work.embeddings, names, method=args.method, seed=42,
                                      out_pkl=work.reduced_raw, status=status, stop=stop)
    except mapter.ReductionCancelled as exc:
        raise Cancelled() from exc
    _check_stop(stop)
    # The reducer may have fallen back (umap-learn missing, tiny input): record what ran.
    used = (df.attrs.get("mapter_reduce") or {}).get("method_used")
    if used:
        ctx["method_used"] = used
        if used != args.method:
            logger.warning(f"[reduce] method '{args.method}' was run as '{used}'")
    if not work.reduced_raw.exists():  # reducer returned the frame without writing it
        from pipeline.common import atomic_to_pickle
        atomic_to_pickle(df, work.reduced_raw)
    logger.info(f"[reduce] {len(df)} functions on the map")


def stage_merge(ctx: dict) -> None:
    work, status, args = ctx["work"], ctx["status"], ctx["args"]
    from pipeline import merge_stage
    status.stage("merge", total=1, message="Building the data folder")
    ctx["out"] = merge_stage.run(work, ctx["manifest"], ctx["binary_names"], ctx["name"],
                                 ctx.get("method_used") or args.method,
                                 app_dir=Path(args.app_dir) if args.app_dir else None,
                                 out_dir=Path(args.out))
    status.progress(done=1)


STAGE_FUNCS = {"safe": stage_safe, "capa": stage_capa, "avclass": stage_avclass,
               "reduce": stage_reduce, "merge": stage_merge}


def _force_cleanup(work: WorkDir, stages: List[str]) -> None:
    """--force: delete the outputs of the selected stages (VT reports are a
    download cache and are kept)."""
    targets: List[Path] = []
    if "safe" in stages:
        targets += list(work.embeddings.glob("*.pkl"))
    if "capa" in stages:
        targets += list(work.capa_raw.glob("*.json")) + list(work.capa.glob("*.json"))
    if "avclass" in stages:
        targets.append(work.avclass)
    if "reduce" in stages:
        targets.append(work.reduced_raw)
    for t in targets:
        try:
            t.unlink()
        except FileNotFoundError:
            pass
    logger.info(f"--force: removed {len(targets)} previous outputs")


# --------------------------------------------------------------------------- main
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="MAPTER generation pipeline", formatter_class=argparse.RawTextHelpFormatter,
                                 epilog=__doc__.split("Examples::")[0])
    ap.add_argument("--work", help="work folder (required unless --check)")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--binaries", help="folder of binaries to analyse")
    src.add_argument("--manifest", help="manifest.json (default: <work>/manifest.json if present)")
    ap.add_argument("--out", help="data folder to write (default <work>/data_folder)")
    ap.add_argument("--name", help="dataset name (default: folder / project name)")
    ap.add_argument("--stages", default=",".join(STAGES), help=f"comma list of {','.join(STAGES)} (default all)")
    ap.add_argument("--model-dir", default=str(BACKEND_DIR / "model"), help="folder with SAFEtorch.pt and word2id.json")
    ap.add_argument("--r2", help="path to radare2 (>= 6.0)")
    ap.add_argument("--capa", help="path to the capa executable")
    ap.add_argument("--vt-reports", help="folder with VirusTotal reports named <sha256>.json")
    ap.add_argument("--vt-fetch", action="store_true", help="fetch reports from VirusTotal (key in env VT_API_KEY)")
    ap.add_argument("--method", default="tsne", choices=["tsne", "umap", "pca", "fixed"])
    ap.add_argument("--workers", type=int, default=max(1, min(4, os.cpu_count() or 1)))
    ap.add_argument("--r2-timeout", type=int, default=1800, help="seconds per binary for radare2+SAFE")
    ap.add_argument("--capa-timeout", type=int, default=3600,
                    help="seconds per binary for capa (vivisect often needs 5-20 min per binary)")
    ap.add_argument("--app-dir", help="MAPTER Dash app folder (for recommend_delta); default: parent of this folder")
    ap.add_argument("--force", action="store_true", help="ignore previous outputs of the selected stages")
    ap.add_argument("--check", action="store_true", help="print a JSON prerequisite report and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def run_check(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, stream=sys.stderr)
    report = check_prerequisites(Path(args.model_dir), args.r2, args.capa)
    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    return EXIT_OK if report["ok"] else EXIT_FAILED


def _install_signals(stop: StopFlag, on_force) -> None:
    """First SIGTERM/SIGINT sets the StopFlag (finish current binary); a second one
    stops immediately."""
    count = {"n": 0}

    def handler(signum, _frame):
        count["n"] += 1
        if count["n"] == 1:
            logger.warning(f"signal {signum}: stopping after the current binary "
                           f"(send again to stop now)")
            stop.set()
        else:
            on_force()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, handler)


def run_pipeline(args: argparse.Namespace) -> int:
    if not args.work:
        sys.stderr.write("error: --work is required\n")
        return EXIT_FAILED
    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    bad = [s for s in stages if s not in STAGES]
    if bad or not stages:
        sys.stderr.write(f"error: unknown stage(s) {bad or args.stages}; valid: {','.join(STAGES)}\n")
        return EXIT_FAILED
    stages = [s for s in STAGES if s in stages]  # canonical order

    work = WorkDir(Path(args.work).expanduser().resolve()).create()
    args.out = str(Path(args.out).expanduser().resolve()) if args.out else str(work.data_folder)
    if not args.app_dir and (BACKEND_DIR.parent / "recommend_delta.py").is_file():
        args.app_dir = str(BACKEND_DIR.parent)

    try:
        acquire_lock(work.lock)
    except PipelineError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_FAILED

    # Survive the launching process (Ghidra), but keep Ctrl-C working in a terminal.
    if hasattr(os, "setsid") and not sys.stdin.isatty():
        try:
            os.setsid()
        except OSError:
            pass

    setup_logging(work.log, args.verbose)
    status = Status(work.status, stages)
    stop = StopFlag()

    def force_stop() -> None:
        status.finish("cancelled", error="stopped by signal")
        release_lock(work.lock)
        os._exit(EXIT_CANCELLED)

    _install_signals(stop, force_stop)
    logger.info(f"MAPTER pipeline pid {os.getpid()} work={work.root} stages={','.join(stages)} "
                f"method={args.method}")

    try:
        # ---- input
        if args.binaries:
            manifest = scan_folder(Path(args.binaries).expanduser(), work, status, stop)
        else:
            mpath = Path(args.manifest).expanduser() if args.manifest else work.manifest
            if not mpath.is_file():
                raise PipelineError("no input: give --binaries DIR or --manifest FILE "
                                    "(or put manifest.json in the work folder)")
            manifest = load_input_manifest(mpath, work)
        oks = ok_binaries(manifest)
        skipped = [b for b in manifest.get("binaries", []) if b not in oks]
        for b in skipped:
            logger.warning(f"Not processed: {b.get('program_name') or b.get('sha256')}: "
                           f"{b.get('reason') or b.get('status')}")
        if not oks:
            raise PipelineError("no binaries to process")
        binary_names = assign_binary_names(b["sha256"] for b in oks)
        for b in manifest["binaries"]:
            if b.get("sha256") in binary_names:
                b["binary_name"] = binary_names[b["sha256"]]
        atomic_write_json(work.manifest, manifest)
        name = args.name or manifest.get("project") or work.root.name
        logger.info(f"{len(oks)} binaries, binary_name length {len(next(iter(binary_names.values())))}")

        if args.force:
            _force_cleanup(work, stages)
        if "merge" in stages and "reduce" not in stages and not work.reduced_raw.exists():
            raise PipelineError(f"stage merge needs {work.reduced_raw.name}; run the reduce stage first")

        ctx = {"work": work, "status": status, "stop": stop, "args": args, "manifest": manifest,
               "binaries": oks, "binary_names": binary_names, "name": name, "out": Path(args.out)}
        for stage in stages:
            _check_stop(stop)
            t0 = time.time()
            STAGE_FUNCS[stage](ctx)
            _check_stop(stop)
            logger.info(f"stage {stage} finished in {time.time() - t0:.1f}s")

        out = str(ctx["out"]) if "merge" in stages else None
        status.finish("done", out=out)
        logger.info(f"Pipeline finished" + (f": {out}" if out else ""))
        return EXIT_OK
    except Cancelled:
        logger.warning("Pipeline cancelled; per-binary outputs are kept (rerun to resume)")
        status.finish("cancelled")
        return EXIT_CANCELLED
    except PipelineError as exc:
        logger.error(str(exc))
        status.finish("failed", error=str(exc))
        return EXIT_FAILED
    except Exception as exc:  # noqa: BLE001
        if stop.is_set():  # a stage gave up because of the stop request
            logger.warning(f"Pipeline cancelled ({type(exc).__name__}: {exc})")
            status.finish("cancelled")
            return EXIT_CANCELLED
        logger.exception("Pipeline failed")
        status.finish("failed", error=f"{type(exc).__name__}: {exc}")
        return EXIT_FAILED
    finally:
        release_lock(work.lock)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.check:
        return run_check(args)
    return run_pipeline(args)


if __name__ == "__main__":
    sys.exit(main())
