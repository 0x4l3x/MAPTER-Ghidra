"""
VirusTotal v3 file-report fetcher (library + standalone CLI).

``GET https://www.virustotal.com/api/v3/files/{sha256}`` with the ``x-apikey``
header, one report per sample, saved as ``<out_dir>/<sha256>.json`` in
single-line (compact) JSON, which is what AVClass reads.

* Lookup only: files are NEVER uploaded. HTTP 404 means VirusTotal does not
  know the sample; it is recorded in ``<out_dir>/vt_unknown.json`` and is not
  asked again for ``unknown_ttl_days`` days (or until ``force``).
* Resumable: existing non-empty reports are skipped.
* Paced: at least ``pacing`` seconds between requests (15 s = free key, 4
  requests/minute). 429 is retried with ``Retry-After`` / growing backoff,
  5xx and network errors with exponential backoff. When 429 persists, or the
  key is rejected (401/403), the whole run stops and the remaining samples are
  left for a later resume instead of hammering the API.
* The API key only ever travels in the request header: it is never written to
  disk or to the log. The CLI reads it from the environment (``VT_API_KEY``),
  not from argv, so it does not show up in ``ps``.

CLI::

    VT_API_KEY=... python vt_fetch.py --out reports/ --sha256 <h1> <h2>
    VT_API_KEY=... python vt_fetch.py --out reports/ --list hashes.txt
    VT_API_KEY=... python vt_fetch.py --out reports/ --binaries folder/
"""
from __future__ import annotations

import argparse
import http.client
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, Optional, Tuple

from pipeline.common import atomic_write_json, atomic_write_text, is_done, sha256_file

logger = logging.getLogger("mapter.vt")

VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
UNKNOWN_FILE = "vt_unknown.json"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

#: transport(url, headers, timeout) -> (http status, response headers, body).
#: Raises OSError/URLError/HTTPException on network failures.
Transport = Callable[[str, Mapping[str, str], float], Tuple[int, Mapping[str, str], bytes]]


class VTAbort(Exception):
    """The run cannot continue (bad key, persistent rate limit)."""


def urllib_transport(url: str, headers: Mapping[str, str], timeout: float) -> Tuple[int, Mapping[str, str], bytes]:
    """Default transport: one HTTPS GET with urllib (HTTP errors are returned, not raised)."""
    import ssl
    try:  # certifi (a dependency of requests) avoids missing CA bundles on some macOS Pythons
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        try:
            body = err.read()
        except Exception:
            body = b""
        return err.code, dict(err.headers or {}), body


def _retry_after(headers: Mapping[str, str]) -> Optional[float]:
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except (TypeError, ValueError):
                return None
    return None


def _error_text(body: bytes) -> str:
    """Short VT error description ('Code: message') from an error body."""
    try:
        err = json.loads(body.decode("utf-8", "replace")).get("error", {})
        return f"{err.get('code', '')}: {err.get('message', '')}".strip(": ")[:200]
    except Exception:
        return ""


class _Fetcher:
    def __init__(self, api_key: str, pacing: float, max_retries: int, timeout: float,
                 transport: Transport, sleep: Callable[[float], None],
                 monotonic: Callable[[], float], stop):
        self._headers = {"x-apikey": api_key, "accept": "application/json"}
        self.pacing = max(0.0, pacing)
        self.max_retries = max_retries
        self.timeout = timeout
        self.transport = transport
        self._sleep = sleep
        self._monotonic = monotonic
        self.stop = stop
        self._last_request: Optional[float] = None

    def stopped(self) -> bool:
        return self.stop is not None and self.stop.is_set()

    def wait(self, seconds: float) -> bool:
        """Sleep `seconds` in short slices; False if stop was requested meanwhile."""
        end = self._monotonic() + seconds
        while True:
            if self.stopped():
                return False
            left = end - self._monotonic()
            if left <= 0:
                return True
            self._sleep(min(left, 0.5))

    def _pace(self) -> bool:
        if self._last_request is not None:
            gap = self.pacing - (self._monotonic() - self._last_request)
            if gap > 0 and not self.wait(gap):
                return False
        return not self.stopped()

    def get(self, sha256: str) -> Tuple[str, object]:
        """One report lookup. Returns ('ok', report dict) | ('unknown', None) |
        ('error', reason) | ('stopped', None); raises VTAbort."""
        url = VT_FILE_URL.format(sha256=sha256)
        last_reason = "no attempt made"
        for attempt in range(self.max_retries + 1):
            if not self._pace():
                return "stopped", None
            self._last_request = self._monotonic()
            try:
                code, headers, body = self.transport(url, self._headers, self.timeout)
            except (OSError, http.client.HTTPException) as exc:
                last_reason = f"network error: {type(exc).__name__}: {exc}"
                delay = min(5.0 * 2 ** attempt, 60.0)
            else:
                if code == 200:
                    try:
                        report = json.loads(body.decode("utf-8"))
                        report["data"]["attributes"]  # noqa: B018 - shape check
                    except (ValueError, KeyError, TypeError, AttributeError):
                        return "error", "HTTP 200 but the body is not a VT file report"
                    return "ok", report
                if code == 404:
                    return "unknown", None
                if code in (401, 403):
                    raise VTAbort(f"HTTP {code}: the API key was rejected ({_error_text(body) or 'forbidden'})")
                if code == 429:
                    last_reason = f"HTTP 429 rate limited ({_error_text(body) or 'quota'})"
                    delay = _retry_after(headers)
                    if delay is None:
                        delay = 60.0 * (attempt + 1)
                    delay = min(delay, 600.0)
                    if attempt == self.max_retries:
                        raise VTAbort(f"{last_reason}; giving up, resume later")
                elif code == 408 or code >= 500:
                    last_reason = f"HTTP {code} {_error_text(body)}".strip()
                    delay = min(5.0 * 2 ** attempt, 120.0)
                else:
                    return "error", f"HTTP {code} {_error_text(body)}".strip()
            if attempt == self.max_retries:
                break
            logger.warning(f"VT {sha256[:12]}...: {last_reason}; retry {attempt + 1}/{self.max_retries} in {delay:.0f}s")
            if not self.wait(delay):
                return "stopped", None
        return "error", last_reason


def _load_unknown(out_dir: Path) -> Dict[str, float]:
    try:
        data = json.loads((out_dir / UNKNOWN_FILE).read_text(encoding="utf-8"))
        return {k: float(v) for k, v in data.items()}
    except (OSError, ValueError, AttributeError, TypeError):
        return {}


def fetch_reports(sha256s: Iterable[str], out_dir: Path, api_key: str, *,
                  pacing: float = 15.0, max_retries: int = 4, timeout: float = 30.0,
                  unknown_ttl_days: float = 7.0, force: bool = False, stop=None,
                  on_progress: Optional[Callable[[str, str], None]] = None,
                  transport: Optional[Transport] = None,
                  sleep: Callable[[float], None] = time.sleep,
                  monotonic: Callable[[], float] = time.monotonic) -> Dict[str, str]:
    """Download the VT v3 report of every sha256 into ``out_dir/<sha256>.json``.

    Returns ``{sha256: status}`` with status one of ``ok`` (fetched now),
    ``cached`` (report already present), ``unknown`` (VT answered 404; not
    uploaded), ``error: <reason>``, ``skipped: <reason>`` (run aborted or
    stopped before reaching it). `on_progress(sha256, status)` is called per
    sample. Never raises for API problems; the key is never logged or stored.
    """
    if not api_key:
        raise ValueError("a VirusTotal API key is required")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    shas = list(dict.fromkeys(s.lower() for s in sha256s))
    results: Dict[str, str] = {}
    unknown = {} if force else _load_unknown(out_dir)
    ttl = unknown_ttl_days * 86400.0
    fetcher = _Fetcher(api_key, pacing, max_retries, timeout, transport or urllib_transport,
                       sleep, monotonic, stop)

    def record(sha: str, status: str) -> None:
        results[sha] = status
        if on_progress is not None:
            on_progress(sha, status)

    abort_reason: Optional[str] = None
    for sha in shas:
        if not _SHA256_RE.match(sha):
            record(sha, "error: not a sha256")
            continue
        path = out_dir / f"{sha}.json"
        if not force and is_done(path):
            record(sha, "cached")
            continue
        if not force and sha in unknown and time.time() - unknown[sha] < ttl:
            record(sha, "unknown")
            continue
        if abort_reason is not None:
            record(sha, f"skipped: {abort_reason}")
            continue
        if fetcher.stopped():
            record(sha, "skipped: stop requested")
            continue
        try:
            kind, payload = fetcher.get(sha)
        except VTAbort as exc:
            abort_reason = str(exc)
            logger.error(f"VirusTotal fetch aborted: {abort_reason}")
            record(sha, f"skipped: {abort_reason}")
            continue
        if kind == "ok":
            atomic_write_text(path, json.dumps(payload, separators=(",", ":")) + "\n")
            unknown.pop(sha, None)
            record(sha, "ok")
        elif kind == "unknown":
            unknown[sha] = time.time()
            atomic_write_json(out_dir / UNKNOWN_FILE, unknown)
            logger.info(f"VT {sha[:12]}...: unknown to VirusTotal (not uploaded)")
            record(sha, "unknown")
        elif kind == "stopped":
            record(sha, "skipped: stop requested")
        else:
            logger.warning(f"VT {sha[:12]}...: {payload}")
            record(sha, f"error: {payload}")
    return results


# --------------------------------------------------------------------------- CLI
def _read_hash_list(path: Path) -> list:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.replace(",", " ").split()[0])
    return out


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Download VirusTotal v3 file reports (lookup only, never uploads). "
                    "API key from the VT_API_KEY environment variable.")
    ap.add_argument("--out", required=True, type=Path, help="directory for <sha256>.json reports")
    src = ap.add_argument_group("samples (any combination)")
    src.add_argument("--sha256", nargs="+", default=[], metavar="HASH")
    src.add_argument("--list", type=Path, help="text file, one sha256 per line (CSV: first column)")
    src.add_argument("--binaries", type=Path, help="folder of files to hash (regular files, not recursive)")
    ap.add_argument("--pacing", type=float, default=15.0, help="seconds between requests (15 = free key)")
    ap.add_argument("--max-retries", type=int, default=4)
    ap.add_argument("--unknown-ttl-days", type=float, default=7.0,
                    help="do not re-query samples VT answered 404 for this long")
    ap.add_argument("--force", action="store_true", help="re-download existing reports, re-query unknown ones")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        logger.error("VT_API_KEY is not set")
        return 1
    shas = list(args.sha256)
    if args.list:
        shas += _read_hash_list(args.list)
    if args.binaries:
        shas += [sha256_file(p) for p in sorted(args.binaries.iterdir()) if p.is_file()]
    if not shas:
        logger.error("no samples given (--sha256, --list or --binaries)")
        return 1

    results = fetch_reports(shas, args.out, api_key, pacing=args.pacing,
                            max_retries=args.max_retries, unknown_ttl_days=args.unknown_ttl_days,
                            force=args.force,
                            on_progress=lambda s, st: logger.info(f"{s[:12]}... {st}"))
    counts: Dict[str, int] = {}
    for st in results.values():
        key = st.split(":", 1)[0]
        counts[key] = counts.get(key, 0) + 1
    logger.info("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 1 if counts.get("error") or counts.get("skipped") else 0


if __name__ == "__main__":
    sys.exit(main())
