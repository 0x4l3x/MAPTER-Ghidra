"""
AVClass stage of the MAPTER pipeline.

Per binary: a VirusTotal v3 report (from ``reports_dir/<sha256>.json`` or
``work.vt_reports/<sha256>.json``, optionally downloaded first) is labelled with
avclass-malicialab and the result goes into ``work.avclass`` (avclass.pkl).
Binaries without a report simply get no row (the app shows them as Unknown).
The stage is optional: without avclass or without any report it is skipped and
``run`` returns None.

Offline by default. Downloading (``fetch=True`` + ``api_key``) only ever looks
samples up by hash; unknown samples are never uploaded (see ``vt_fetch``).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from pipeline.common import StopFlag, Status, WorkDir, atomic_to_pickle

logger = logging.getLogger("mapter.pipeline.avclass")

STAGE = "avclass"


def _find_report(sha256: str, *dirs: Optional[Path]) -> Optional[Path]:
    for d in dirs:
        if d is None:
            continue
        for suffix in (".json", ".json.gz"):
            p = Path(d) / f"{sha256}{suffix}"
            if p.is_file() and p.stat().st_size > 0:
                return p
    return None


def run(work: WorkDir, binaries: List[dict], status: Status, stop: StopFlag,
        binary_names: Dict[str, str], reports_dir: Optional[Path] = None,
        api_key: Optional[str] = None, fetch: bool = False, *,
        workers: Optional[int] = None, pacing: float = 15.0) -> Optional[Path]:
    """Run the AVClass stage; returns ``work.avclass`` or None when skipped.

    `binaries` are the manifest entries to process, `binary_names` the
    sha256 -> binary_name map of the whole run. `reports_dir` holds
    user-supplied reports named ``<sha256>.json``. With `fetch` and an
    `api_key`, reports still missing are downloaded into ``work.vt_reports``
    (resumable, paced `pacing` seconds per request, no uploads). `workers`
    defaults to min(4, cpu_count).
    """
    import avclass_processer as ap  # backend root; imported lazily (needs pandas)

    if not ap.avclass_available():
        logger.warning("avclass-malicialab is not installed: AVClass stage skipped "
                       "(pip install avclass-malicialab)")
        return None

    shas = list(dict.fromkeys(b["sha256"].lower() for b in binaries))
    reports_dir = Path(reports_dir) if reports_dir else None
    work.vt_reports.mkdir(parents=True, exist_ok=True)

    # 1. optional VirusTotal download of the reports that are still missing
    if fetch:
        missing = [s for s in shas if _find_report(s, work.vt_reports, reports_dir) is None]
        if not api_key:
            logger.warning("VirusTotal fetch requested but no API key (VT_API_KEY): skipping download")
        elif missing:
            from vt_fetch import fetch_reports  # backend root
            status.stage(STAGE, total=len(missing),
                         message=f"downloading {len(missing)} VirusTotal reports ({pacing:g}s per request)")

            def progress(sha: str, st: str) -> None:
                status.progress(advance=1, current=binary_names.get(sha, sha[:12]))
                if st.startswith("error"):
                    status.failure(STAGE, binary_names.get(sha, sha[:12]), f"VirusTotal: {st}")

            results = fetch_reports(missing, work.vt_reports, api_key, pacing=pacing, stop=stop,
                                    on_progress=progress)
            counts: Dict[str, int] = {}
            for st in results.values():
                counts[st.split(":", 1)[0]] = counts.get(st.split(":", 1)[0], 0) + 1
            logger.info("VirusTotal download: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
            if stop.is_set():
                return None

    # 2. collect the reports that exist
    report_files: Dict[str, Path] = {}
    for sha in shas:
        p = _find_report(sha, work.vt_reports, reports_dir)
        if p is not None:
            report_files[sha] = p
    if not report_files:
        logger.warning("no VirusTotal reports available: AVClass stage skipped "
                       "(give --vt-reports DIR or --vt-fetch with VT_API_KEY)")
        return None

    # 3. label
    status.stage(STAGE, total=len(report_files), message=f"labelling {len(report_files)} reports")
    path_to_sha = {str(p): s for s, p in report_files.items()}
    n_workers = workers if workers is not None else min(4, os.cpu_count() or 1)

    def on_result(path: str, record: Optional[dict], error: Optional[str]) -> None:
        sha = path_to_sha.get(path, "")
        name = binary_names.get(sha, sha[:12])
        status.progress(advance=1, current=name)
        if record is None:
            status.failure(STAGE, name, f"AVClass: {error}")

    records, failures = ap.label_reports(list(path_to_sha), workers=n_workers,
                                         on_result=on_result, stop=stop)
    if stop.is_set():
        return None
    # a report that is for another sample than its file name says was rejected in label_report
    df = ap.build_avclass_frame(records, binary_names)
    if df.empty:
        logger.warning(f"AVClass labelled none of {len(report_files)} reports: stage skipped")
        return None
    atomic_to_pickle(df, work.avclass)
    logger.info(f"AVClass: {len(df)} labelled, {len(failures)} failed, "
                f"{len(shas) - len(report_files)} binaries without a report -> {work.avclass}")
    return work.avclass
