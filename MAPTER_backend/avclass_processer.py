"""
AVClass2 labelling of VirusTotal reports (library + CLI).

Reads VirusTotal file reports (one report per file, JSON on a single line, v3
by default; v2, "lb" and OPSWAT reports are accepted by AVClass too), runs
``avclass-malicialab`` (``avclass.labeler.FileLabeler``) over them and produces
one row per report: the AVClass ranked tags split into columns plus the
``label`` the MAPTER app uses.

Label rule (reproduces ``datasets/APT_19/avclass.pkl``)::

    description == '[]' (the report has no AV labels)  -> '-'
    first FAM:/UNK: tag of the ranked description        -> that tag's name
    otherwise                                            -> 'None'

One ``FileLabeler`` is built per process (parsing the ~6.5k tagging rules is
the expensive part) and reused for every report that process handles.
``avclass`` is imported lazily so this module can be imported (and
``avclass_available()`` asked) without the package installed.

CLI::

    python avclass_processer.py --reports-dir DIR --out-pkl avclass.pkl \
        [--out-csv avclass.csv] [--workers 4] [--apt-group NAME] \
        [--binary-names names.json]

Failed reports (invalid JSON, unknown format, labeler errors) are skipped and
logged; they never produce a row.
"""
from __future__ import annotations

import argparse
import contextlib
import gzip
import io
import json
import logging
import multiprocessing
import os
import re
import signal
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import pandas as pd

logger = logging.getLogger("mapter.avclass")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

#: Columns of the frame written by ``build_avclass_frame`` (``apt_group`` only
#: when requested). The app reads just ``binary_name`` and ``label``.
FRAME_COLUMNS = [
    "binary_name", "label", "sha256", "number_avs", "family", "family_count",
    "behavior", "behavior_count", "class", "class_count", "filetype",
    "filetype_count", "unknown", "unknown_count", "extra_information",
    "description",
]


class ReportError(Exception):
    """A report that could not be labelled (the message is the reason)."""


# --------------------------------------------------------------------------- avclass import
_AVCLASS = None  # (FileLabeler, tag_path, exp_path, tax_path) once imported


def _import_avclass():
    """Import avclass once, undoing its logging side effects.

    ``avclass.labeler`` sets the *root* logger to DEBUG and attaches a stderr
    handler at import time, which would flood the pipeline log, so the root
    logger is restored and the avclass logger is limited to errors.
    """
    global _AVCLASS
    if _AVCLASS is None:
        root = logging.getLogger()
        level, handlers = root.level, list(root.handlers)
        try:
            from avclass.labeler import FileLabeler
            from avclass import DEFAULT_TAX_PATH, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH
        finally:
            root.setLevel(level)
            for h in list(root.handlers):
                if h not in handlers:
                    root.removeHandler(h)
        logging.getLogger("avclass").setLevel(logging.ERROR)
        _AVCLASS = (FileLabeler, DEFAULT_TAG_PATH, DEFAULT_EXP_PATH, DEFAULT_TAX_PATH)
    return _AVCLASS


def avclass_available() -> bool:
    """True when avclass-malicialab can be imported."""
    try:
        _import_avclass()
        return True
    except Exception as exc:  # ImportError, or a broken install
        logger.debug(f"avclass not importable: {exc}")
        return False


# --------------------------------------------------------------------------- parsing AVClass output
def process_description(description) -> dict:
    """
    Processes a single description string from the AVClass output.
    Only keeps the first occurrence of each description field type (CLASS, FILE, FAM, BEH, UNK)
    along with its associated count. Converts abbreviated field names to full names.
    Any remaining description parts are captured in the extra_information field.

    Args:
    - description: String with the ranked tags of the AVClass output
      (e.g. ``FILE:os:windows|19,BEH:server|4,UNK:sluegot|4``).

    Returns:
    - Dictionary with parsed information organized by field type using descriptive names.
    """
    result = {
        'class': None,
        'class_count': 0,
        'filetype': None,
        'filetype_count': 0,
        'avclass_family': None,
        'avclass_family_count': 0,
        'behavior': None,
        'behavior_count': 0,
        'unknown': None,
        'unknown_count': 0,
        'extra_information': None,
    }
    if description is None or description == "[]" or isinstance(description, float) or description == "":
        return result
    field_mapping = {
        'CLASS': 'class',
        'FILE': 'filetype',
        'FAM': 'avclass_family',
        'BEH': 'behavior',
        'UNK': 'unknown',
    }
    if not isinstance(description, str):
        raise AttributeError("Description is not a string.")
    parts = [part.strip() for part in description.split(',')]
    seen_fields = set()
    extra_parts = []

    for part in parts:
        if ':' not in part:
            extra_parts.append(part)
            continue

        # Split by first colon to handle cases where values might contain colons
        field_type, field_value = part.split(':', 1)

        # Skip if we've already processed this field type
        if field_type in seen_fields:
            extra_parts.append(part)
            continue
        seen_fields.add(field_type)

        count = 1
        if '|' in field_value:
            field_value, count_str = field_value.split('|', 1)
            try:
                count = int(count_str)
            except ValueError:
                count = 1  # malformed count

        descriptive_name = field_mapping.get(field_type, field_type)
        result[descriptive_name] = field_value.strip()
        result[f"{descriptive_name}_count"] = count

    if extra_parts:
        result["extra_information"] = ", ".join(extra_parts)
    return result


def derive_label(description) -> str:
    """The MAPTER label of a ranked AVClass description (see module docstring)."""
    if description is None or isinstance(description, float):
        return "-"
    description = str(description).strip()
    if description == "[]":
        return "-"
    for part in description.split(","):
        part = part.strip()
        if part.startswith(("FAM:", "UNK:")):
            return part.split(":", 1)[1].split("|", 1)[0].strip() or "None"
    return "None"


def process_av_output(output: str) -> dict:
    """
    Processes the output line of the AVClass tool over one file.

    Args:
    - output: ``<name>\\t<n_avs>\\t<ranked tags>`` or ``<name>\\t-\\t[]`` (no AV labels).

    Returns:
    - Dictionary containing the processed output: ``name``, ``av_malware_tags``
      (number of AV engines with a label), ``description``, ``label`` and the
      fields of ``process_description``.
    """
    output_fields = output.rstrip("\n").split("\t")
    if len(output_fields) < 2:
        raise ReportError(f"unexpected AVClass output: {output!r}")
    record = {"name": output_fields[0]}
    if output_fields[1] != "-":
        record["av_malware_tags"] = int(output_fields[1])
        description = ",".join(output_fields[2:])
    else:
        record["av_malware_tags"] = 0
        description = "[]"
    record["description"] = description
    record["label"] = derive_label(description)
    record.update(process_description(description))
    return record


# --------------------------------------------------------------------------- labelling
def _make_labeler():
    FileLabeler, tag, exp, tax = _import_avclass()
    buffer = io.StringIO()
    labeler = FileLabeler(out_fd=buffer, tag_file=tag, exp_file=exp, tax_file=tax,
                          hash_type="sha256", output_all_tags=True)
    return labeler, buffer


_WORKER = None  # (labeler, buffer): one per process


def _worker_labeler():
    global _WORKER
    if _WORKER is None:
        _WORKER = _make_labeler()
    return _WORKER


def _run_labeler(labeler, buffer, path: str) -> str:
    """Run the labeler on one file; return its output line (stderr captured)."""
    buffer.seek(0)
    buffer.truncate(0)
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        labeler.process_file(path)
    output = buffer.getvalue()
    if not output.strip():
        # FileLabeler swallows per-line errors (prints the traceback to stderr).
        err = [ln for ln in captured.getvalue().splitlines() if ln.strip()]
        tail = err[-1].strip() if err else "no output"
        raise ReportError(f"AVClass produced no output ({tail})")
    return output


def _stem_sha256(path: str) -> Optional[str]:
    stem = os.path.basename(path).split(".")[0].lower()
    return stem if _SHA256_RE.match(stem) else None


def _compact_copy(path: str, tmpdir: str) -> str:
    """Rewrite a pretty-printed JSON report as single-line JSON (AVClass reads the
    first line only)."""
    with open(path, "rb") as raw:
        opener = gzip.open if raw.read(2) == b"\x1f\x8b" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        obj = json.load(fh)
    out = os.path.join(tmpdir, os.path.basename(path).split(".")[0] + ".json")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
    return out


def label_report(file_path: str, labeler=None, buffer=None) -> dict:
    """Label one report file with AVClass.

    Uses this process's shared labeler unless one is given. Returns a record
    (see ``process_av_output``) with ``sha256`` (the report's own hash) and
    ``file``; raises ``ReportError`` with the reason when the report cannot be
    labelled or belongs to another sample than its file name says.
    """
    if labeler is None:
        labeler, buffer = _worker_labeler()
    try:
        try:
            output = _run_labeler(labeler, buffer, file_path)
        except json.JSONDecodeError:
            # pretty-printed (multi-line) report: normalise to one line and retry
            with tempfile.TemporaryDirectory(prefix="mapter-vt-") as tmp:
                try:
                    output = _run_labeler(labeler, buffer, _compact_copy(file_path, tmp))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ReportError(f"invalid JSON ({exc})") from exc
    except ReportError:
        raise
    except KeyError as exc:
        raise ReportError(f"unsupported report format (missing {exc})") from exc
    except Exception as exc:
        raise ReportError(f"{type(exc).__name__}: {exc}") from exc

    record = process_av_output(output.splitlines()[0])
    report_sha = record.pop("name").lower()
    stem_sha = _stem_sha256(file_path)
    if not _SHA256_RE.match(report_sha):
        report_sha = stem_sha  # report without a usable hash: trust the file name
    elif stem_sha and stem_sha != report_sha:
        raise ReportError(f"report is for sha256 {report_sha[:12]}..., file name says {stem_sha[:12]}...")
    if not report_sha:
        raise ReportError("cannot determine the sample sha256 (not in the report or the file name)")
    record["sha256"] = report_sha
    record["file"] = os.path.basename(file_path)
    return record


def _worker_job(path: str) -> Tuple[str, Optional[dict], Optional[str]]:
    """Pool worker: (path, record | None, error reason | None)."""
    try:
        return path, label_report(path), None
    except ReportError as exc:
        return path, None, str(exc)
    except Exception as exc:  # never let one report kill the pool
        return path, None, f"{type(exc).__name__}: {exc}"


def _worker_init() -> None:
    # the parent handles Ctrl-C / SIGTERM; workers just get terminated
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def label_reports(file_paths: Iterable[str], workers: int = 1,
                  on_result: Optional[Callable[[str, Optional[dict], Optional[str]], None]] = None,
                  stop=None) -> Tuple[List[dict], Dict[str, str]]:
    """Label many report files.

    `workers` > 1 uses a spawn process pool (each worker builds one labeler);
    small inputs (< 8 files) run in this process. `on_result(path, record,
    error)` is called per file as results arrive; `stop` (anything with
    ``is_set()``) ends the run early. Returns ``(records, failures)`` where
    failures maps file path -> reason.
    """
    paths = [str(p) for p in file_paths]
    records: List[dict] = []
    failures: Dict[str, str] = {}

    def handle(path, record, error):
        if record is not None:
            records.append(record)
        else:
            failures[path] = error or "unknown error"
            logger.warning(f"AVClass skipped {os.path.basename(path)}: {failures[path]}")
        if on_result is not None:
            on_result(path, record, error)

    if workers <= 1 or len(paths) < 8:
        for path in paths:
            if stop is not None and stop.is_set():
                break
            handle(*_worker_job(path))
        return records, failures

    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(processes=min(workers, len(paths)), initializer=_worker_init) as pool:
        try:
            for result in pool.imap_unordered(_worker_job, paths, chunksize=4):
                handle(*result)
                if stop is not None and stop.is_set():
                    break
        finally:
            pool.terminate()
    return records, failures


# --------------------------------------------------------------------------- frames
def build_avclass_frame(records: Iterable[dict], binary_names: Dict[str, str],
                        apt_group: Optional[str] = None) -> pd.DataFrame:
    """DataFrame of the avclass.pkl: one row per labelled report.

    `binary_names` maps sha256 -> binary_name (``pipeline.common.assign_binary_names``);
    records whose sha256 is not in it are dropped (logged). Sorted by binary_name.
    """
    rows = []
    for rec in records:
        sha = rec["sha256"]
        name = binary_names.get(sha)
        if name is None:
            logger.warning(f"AVClass: {sha[:12]}... is not in the binary_name mapping, skipped")
            continue
        rows.append({
            "binary_name": name,
            "label": rec["label"],
            "sha256": sha,
            "number_avs": int(rec["av_malware_tags"]),
            "family": rec["avclass_family"],
            "family_count": rec["avclass_family_count"],
            "behavior": rec["behavior"],
            "behavior_count": rec["behavior_count"],
            "class": rec["class"],
            "class_count": rec["class_count"],
            "filetype": rec["filetype"],
            "filetype_count": rec["filetype_count"],
            "unknown": rec["unknown"],
            "unknown_count": rec["unknown_count"],
            "extra_information": rec["extra_information"],
            "description": rec["description"],
        })
    df = pd.DataFrame(rows, columns=FRAME_COLUMNS)
    if apt_group:
        df.insert(1, "apt_group", apt_group)
    df = df.sort_values("binary_name", kind="stable").reset_index(drop=True)
    # Plain object/int64 columns: pandas 3 would pickle its own string dtype,
    # which the app's pandas 2.x cannot unpickle.
    for col in df.columns:
        df[col] = df[col].astype("int64") if col == "number_avs" or col.endswith("_count") \
            else df[col].astype(object)
    df.columns = pd.Index(list(df.columns), dtype=object)
    return df


# --------------------------------------------------------------------------- CLI
def list_report_files(reports_dir: Path) -> List[Path]:
    """Regular, non-hidden files of the directory (named ``<sha256>.json[.gz]``)."""
    return sorted(p for p in Path(reports_dir).iterdir()
                  if p.is_file() and not p.name.startswith("."))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Label VirusTotal reports with AVClass2 -> avclass.pkl")
    ap.add_argument("--reports-dir", required=True, type=Path,
                    help="directory with one VirusTotal report per file (<sha256>.json, single-line JSON)")
    ap.add_argument("--out-pkl", required=True, type=Path, help="output pickle (binary_name, label, sha256, ...)")
    ap.add_argument("--out-csv", type=Path, help="optional CSV copy of the same table")
    ap.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    ap.add_argument("--apt-group", help="adds an apt_group column with this value (dataset/folder name)")
    ap.add_argument("--binary-names", type=Path,
                    help="JSON {sha256: binary_name}; default: shortest unique sha256 prefix (>= 6 chars)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    if not avclass_available():
        logger.error("avclass-malicialab is not installed (pip install avclass-malicialab)")
        return 1
    files = list_report_files(args.reports_dir)
    if not files:
        logger.error(f"no reports in {args.reports_dir}")
        return 1

    try:
        from tqdm import tqdm
        bar = tqdm(total=len(files), desc="AVClass", unit="report")
        on_result = lambda *_: bar.update(1)  # noqa: E731
    except ImportError:
        bar, on_result = None, None
    records, failures = label_reports(files, workers=args.workers, on_result=on_result)
    if bar is not None:
        bar.close()

    if args.binary_names:
        names = json.loads(args.binary_names.read_text(encoding="utf-8"))
    else:
        from pipeline.common import assign_binary_names
        names = assign_binary_names(r["sha256"] for r in records)
    df = build_avclass_frame(records, names, args.apt_group)
    args.out_pkl.parent.mkdir(parents=True, exist_ok=True)
    df.to_pickle(args.out_pkl)
    if args.out_csv:
        df.to_csv(args.out_csv, index=False)
    logger.info(f"{len(df)} labelled, {len(failures)} failed -> {args.out_pkl}")
    return 0 if len(df) else 1


if __name__ == "__main__":
    sys.exit(main())
