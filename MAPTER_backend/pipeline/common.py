"""
Shared pieces of the MAPTER generation pipeline (mapter_pipeline.py).

Every stage module imports its paths, binary keys, status reporting and tool
discovery from here, so the stages agree on one contract:

Work folder layout (``WorkDir``)::

    <work>/
      manifest.json          # binaries to process (see Manifest below)
      binaries/<sha256>      # input files, named by lowercase sha256, no extension
      embeddings/<sha256>.pkl   # SAFE stage: DataFrame offset, embeddings, name, size
      capa_raw/<sha256>.json    # capa --json output
      capa/<sha256>.json        # simplified capa (format the app's CapaLoader reads)
      vt_reports/<sha256>.json  # VirusTotal v3 file reports (single-line JSON)
      avclass.pkl               # AVClass stage: binary_name, label, sha256, ...
      reduced_raw.pkl           # reduce stage: x, y, binary_name, offset, name, size, sha256
      data_folder/              # final MAPTER data folder the app loads
        reduced.pkl             #   enriched single pickle (CAPA + avclass columns)
        dataset.json  binaries.json  capa/  avclass.pkl
      status.json  pipeline.log  pipeline.lock

Manifest (``<work>/manifest.json``)::

    {"source": "ghidra" | "folder", "project": "<name or folder>",
     "binaries": [{"sha256": "...", "path": "<work>/binaries/<sha256>",
                   "binary_name": "1b4491", "program_name": "...",
                   "domain_path": "/...", "format": "...",
                   "status": "ok" | "missing" | "error", "reason": "..."}]}

Binary key: ``binary_name`` = first 6 hex chars of the sha256, which is what the
app, its CAPA loader and the existing datasets use; if two binaries of one run
share that prefix, every name in the run is lengthened until all are unique.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import signal
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger("mapter.pipeline")

BINARY_NAME_LENGTH = 6
STAGES = ("safe", "capa", "avclass", "reduce", "merge")


# --------------------------------------------------------------------------- paths
@dataclass(frozen=True)
class WorkDir:
    root: Path

    @property
    def manifest(self) -> Path: return self.root / "manifest.json"
    @property
    def binaries(self) -> Path: return self.root / "binaries"
    @property
    def embeddings(self) -> Path: return self.root / "embeddings"
    @property
    def capa_raw(self) -> Path: return self.root / "capa_raw"
    @property
    def capa(self) -> Path: return self.root / "capa"
    @property
    def vt_reports(self) -> Path: return self.root / "vt_reports"
    @property
    def avclass(self) -> Path: return self.root / "avclass.pkl"
    @property
    def reduced_raw(self) -> Path: return self.root / "reduced_raw.pkl"
    @property
    def data_folder(self) -> Path: return self.root / "data_folder"
    @property
    def status(self) -> Path: return self.root / "status.json"
    @property
    def log(self) -> Path: return self.root / "pipeline.log"
    @property
    def lock(self) -> Path: return self.root / "pipeline.lock"

    def create(self) -> "WorkDir":
        for d in (self.root, self.binaries, self.embeddings, self.capa_raw, self.capa,
                  self.vt_reports, self.data_folder):
            d.mkdir(parents=True, exist_ok=True)
        return self


# --------------------------------------------------------------------------- files
def atomic_write_text(path: Path, text: str) -> None:
    """Write via a temp file + os.replace so readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def atomic_write_json(path: Path, obj) -> None:
    atomic_write_text(path, json.dumps(obj, indent=2, default=str))


def portable_frame(df):
    """Copy of `df` whose string columns / column labels use plain object dtype.

    pandas >= 3 pickles its own string dtype, which pandas 2.x (the Dash app's
    environment may be older than the pipeline's) cannot unpickle. Object dtype
    is readable by every pandas version. Non-DataFrames are returned unchanged.
    """
    try:
        import pandas as pd
    except Exception:  # pragma: no cover - pandas is required by every caller
        return df
    if not isinstance(df, pd.DataFrame):
        return df
    out = df.copy()
    for col in out.columns:
        if isinstance(out[col].dtype, pd.StringDtype) or str(out[col].dtype) == "str":
            out[col] = out[col].astype(object)
    if out.columns.dtype != object:
        out.columns = out.columns.astype(object)
    if out.index.dtype != object and str(out.index.dtype) in ("string", "str"):
        out.index = out.index.astype(object)
    out.attrs = dict(df.attrs)
    return out


def atomic_to_pickle(df, path: Path) -> None:
    """DataFrame.to_pickle via temp file + os.replace (see portable_frame)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    portable_frame(df).to_pickle(tmp)
    os.replace(tmp, path)


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def is_done(path: Path) -> bool:
    """A stage output counts as done when it exists and is non-empty (resume)."""
    return path.exists() and path.stat().st_size > 0


# --------------------------------------------------------------------------- binary keys
def assign_binary_names(sha256s: Iterable[str], length: int = BINARY_NAME_LENGTH) -> Dict[str, str]:
    """{sha256: binary_name}: the shortest common prefix length >= `length` that
    makes every name in the run unique (one length for all, so names stay
    comparable)."""
    shas = sorted({s.lower() for s in sha256s})
    n = length
    while n < 64 and len({s[:n] for s in shas}) < len(shas):
        n += 1
    if n > length:
        logger.warning(f"sha256 prefix collision: binary names lengthened to {n} chars")
    return {s: s[:n] for s in shas}


def load_manifest(work: WorkDir) -> dict:
    return json.loads(work.manifest.read_text(encoding="utf-8"))


def ok_binaries(manifest: dict) -> List[dict]:
    """Manifest entries that can be processed (file present, status ok)."""
    return [b for b in manifest.get("binaries", [])
            if b.get("status", "ok") == "ok" and b.get("path") and os.path.exists(b["path"])]


# --------------------------------------------------------------------------- status
class Status:
    """Progress reporting through <work>/status.json (polled by the Ghidra
    plugin) and the log. Thread-safe; writes are atomic."""

    def __init__(self, path: Path, stages: List[str]):
        self.path = path
        self.stages = list(stages)
        self._lock = threading.Lock()
        self.data = {
            "state": "running", "stage": None, "stage_index": 0,
            "n_stages": len(self.stages), "stages": self.stages, "done": 0, "total": 0,
            "current": None, "message": "", "pid": os.getpid(),
            "started": time.time(), "updated": time.time(), "out": None, "error": None,
            "failures": {},
        }
        self._flush()

    def _flush(self) -> None:
        self.data["updated"] = time.time()
        atomic_write_json(self.path, self.data)

    def stage(self, name: str, total: int = 0, message: str = "") -> None:
        with self._lock:
            self.data.update(stage=name, stage_index=self.stages.index(name) + 1
                             if name in self.stages else 0, done=0, total=total,
                             current=None, message=message or name)
            self._flush()
        logger.info(f"== stage {name}: {message or ''} ({total} items)")

    def progress(self, done: Optional[int] = None, current: Optional[str] = None,
                 message: Optional[str] = None, advance: int = 0) -> None:
        with self._lock:
            if done is not None:
                self.data["done"] = done
            self.data["done"] += advance
            if current is not None:
                self.data["current"] = current
            if message is not None:
                self.data["message"] = message
            self._flush()

    def failure(self, stage: str, key: str, reason: str) -> None:
        """Record a non-fatal per-binary failure (the run continues)."""
        with self._lock:
            self.data["failures"].setdefault(stage, {})[key] = reason
            self._flush()
        logger.warning(f"[{stage}] {key}: {reason}")

    def finish(self, state: str, out: Optional[str] = None, error: Optional[str] = None) -> None:
        with self._lock:
            self.data.update(state=state, out=out, error=error, current=None)
            self._flush()


# --------------------------------------------------------------------------- cancellation
class StopFlag:
    """Set on SIGTERM/SIGINT: stages finish the current binary, then return."""

    def __init__(self):
        self._event = threading.Event()

    def install(self) -> "StopFlag":
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: self._event.set())
        return self

    def is_set(self) -> bool:
        return self._event.is_set()

    def set(self) -> None:
        self._event.set()


# --------------------------------------------------------------------------- tools
# Usual install locations; a Ghidra launched from Finder/Dock has a minimal PATH.
EXTRA_TOOL_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin",
                   str(Path.home() / ".local" / "bin")]


def default_tools_dir() -> Path:
    """Where tools/install_tools.py puts downloaded tools (e.g. capa)."""
    return Path(os.environ.get("MAPTER_TOOLS_DIR", Path.home() / ".mapter" / "tools"))


def find_tool(names: Iterable[str], explicit: Optional[str] = None,
              env_var: Optional[str] = None) -> Optional[str]:
    """Resolve an external tool: explicit path, then $env_var, then the MAPTER
    tools dir, then PATH, then the usual install dirs."""
    for candidate in (explicit, os.environ.get(env_var) if env_var else None):
        if candidate:
            p = Path(candidate).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
            logger.warning(f"Tool not executable: {candidate}")
    names = list(names)
    # Tools installed by tools/install_tools.py win over PATH (e.g. a pip capa without rules).
    for d in (default_tools_dir(), *[default_tools_dir() / n for n in names]):
        for name in names:
            p = d / name
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    search = list(map(Path, EXTRA_TOOL_DIRS))
    for d in search:
        for name in names:
            p = d / name
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
    return None


def tool_env(*tool_paths: Optional[str]) -> Dict[str, str]:
    """Environment for child processes: PATH extended with the tools' dirs and
    the usual install dirs (r2pipe looks up `radare2` on PATH)."""
    env = dict(os.environ)
    dirs = [str(Path(t).parent) for t in tool_paths if t] + EXTRA_TOOL_DIRS
    env["PATH"] = os.pathsep.join(dict.fromkeys(dirs + env.get("PATH", "").split(os.pathsep)))
    return env


def setup_logging(log_path: Optional[Path] = None, verbose: bool = False) -> None:
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        handlers=handlers, force=True)
