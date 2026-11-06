#!/usr/bin/env python3
"""
Install / detect the external tools the MAPTER pipeline needs (stdlib only).

    python install_tools.py capa     [--dest DIR] [--version vX.Y.Z|latest] [--force] [--dry-run]
    python install_tools.py radare2  [--dry-run] [--min-version 6.0]
    python install_tools.py check    [--dest DIR]

* ``capa``: downloads the standalone release zip for this platform from
  https://github.com/mandiant/capa/releases (rules and signatures are embedded),
  verifies the SHA-256 digest published by the GitHub releases API (or, for the
  pinned version, a digest recorded in this file), unzips it to ``DEST/capa/``,
  marks it executable and removes the macOS quarantine flag.
  ``DEST`` defaults to ``$MAPTER_TOOLS_DIR`` or ``~/.mapter/tools`` (the folder
  the pipeline searches, see ``pipeline.common.default_tools_dir``).
* ``radare2``: reports whether radare2 >= 6.0 is available; if not, installs it
  with Homebrew when present, otherwise prints platform instructions (exit 3).
  ``--dry-run`` only reports what it would do.
* ``check``: JSON with what is installed.

Human-readable progress goes to stderr; the last line on stdout is always one
JSON object ``{"tool", "ok", "path", "version", "message"}``.
Exit codes: 0 ok, 1 failed, 3 manual installation needed (radare2).
Nothing is installed system-wide except by ``brew install radare2``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("mapter.install_tools")

#: capa release installed by default (tested with the pipeline's capa_simplifier).
PINNED_CAPA_VERSION = "v9.4.0"
#: sha256 of the pinned release assets, used when the GitHub API gives no digest
#: (offline mirror, rate limit). Values taken from the releases API.
KNOWN_CAPA_DIGESTS: Dict[str, Dict[str, str]] = {
    "v9.4.0": {
        "capa-v9.4.0-linux-arm64.zip": "165df126f05e86736afee0f4c28b19c6037315a99afc3a92a426432cdd30d2c5",
        "capa-v9.4.0-linux.zip": "07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4",
        "capa-v9.4.0-macos-arm64.zip": "119964afc348c80fff93ad8830124a0c55630f179906acb796636c0f8d410672",
        "capa-v9.4.0-macos.zip": "4f45921c756e55dc912ff100ad46427ebb087b88ca6b493f50b015c11ed892e4",
        "capa-v9.4.0-windows.zip": "670ab1a58b81f59cb57533bf4021ac1e7033fbe9b5d5cc180f796976081e3bb5",
    },
}
CAPA_REPO = "mandiant/capa"
MIN_R2_VERSION = (6, 0)
EXIT_OK, EXIT_FAILED, EXIT_MANUAL = 0, 1, 3
USER_AGENT = "mapter-install-tools/1.0"

# Same fallback dirs as pipeline.common.EXTRA_TOOL_DIRS (GUI-launched apps have a short PATH).
EXTRA_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin",
              str(Path.home() / ".local" / "bin")]


# --------------------------------------------------------------------------- helpers
def default_tools_dir() -> Path:
    """``$MAPTER_TOOLS_DIR`` or ``~/.mapter/tools``."""
    return Path(os.environ.get("MAPTER_TOOLS_DIR") or (Path.home() / ".mapter" / "tools"))


def say(msg: str) -> None:
    """Human-readable progress (stderr, so stdout stays machine-readable)."""
    print(msg, file=sys.stderr, flush=True)


def emit(tool: str, ok: bool, path: Optional[str], version: Optional[str], message: str,
         **extra) -> None:
    """Print the final JSON result line on stdout."""
    print(json.dumps({"tool": tool, "ok": ok, "path": path, "version": version,
                      "message": message, **extra}), flush=True)


def _version_tuple(text: Optional[str]) -> Tuple[int, ...]:
    m = re.search(r"(\d+(?:\.\d+)+)", text or "")
    return tuple(int(p) for p in m.group(1).split(".")) if m else ()


def _run(cmd: List[str], timeout: int = 30) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("running %s failed: %s", cmd, exc)
        return None


def _exe(name: str) -> str:
    return name + ".exe" if platform.system() == "Windows" else name


# --------------------------------------------------------------------------- capa
def capa_asset_suffix() -> Optional[str]:
    """Release asset suffix for this platform ('macos-arm64', 'linux', ...) or None."""
    system, machine = platform.system(), platform.machine().lower()
    arm = machine in ("arm64", "aarch64")
    if system == "Darwin":
        return "macos-arm64" if arm else "macos"
    if system == "Linux":
        if arm:
            return "linux-arm64"
        return "linux" if machine in ("x86_64", "amd64") else None
    if system == "Windows":
        return "windows" if machine in ("amd64", "x86_64") else None
    return None


def _http_get(url: str, accept: Optional[str] = None, timeout: int = 60):
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN")
    if token and urllib.parse.urlparse(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout)


def fetch_release(version: str) -> Optional[dict]:
    """Release JSON from the GitHub API ('latest' or a tag); None when unreachable."""
    path = "latest" if version == "latest" else f"tags/{version}"
    url = f"https://api.github.com/repos/{CAPA_REPO}/releases/{path}"
    try:
        with _http_get(url, "application/vnd.github+json") as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise SystemExit(f"capa release '{version}' not found on GitHub")
        logger.warning("GitHub API returned HTTP %s for %s", exc.code, url)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning("GitHub API unreachable (%s)", exc)
    return None


def resolve_capa_asset(version: str) -> Tuple[str, str, Optional[str]]:
    """(tag, download_url, expected_sha256 or None) for this platform."""
    suffix = capa_asset_suffix()
    if suffix is None:
        raise SystemExit(f"No standalone capa build for {platform.system()} {platform.machine()}; "
                         "use 'pip install flare-capa' (see MAPTER_backend/README.md).")
    release = fetch_release(version)
    if release:
        tag = release["tag_name"]
        wanted = f"capa-{tag}-{suffix}.zip"
        for asset in release.get("assets", []):
            if asset["name"] == wanted:
                digest = asset.get("digest") or ""
                sha = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else None
                if sha is None:
                    sha = KNOWN_CAPA_DIGESTS.get(tag, {}).get(wanted)
                return tag, asset["browser_download_url"], sha
        raise SystemExit(f"Release {tag} has no asset {wanted}")
    # API unavailable: direct URL; only the pinned version has a known digest.
    if version == "latest":
        raise SystemExit("GitHub API unreachable; pass --version vX.Y.Z to install a specific release")
    wanted = f"capa-{version}-{suffix}.zip"
    url = f"https://github.com/{CAPA_REPO}/releases/download/{version}/{wanted}"
    return version, url, KNOWN_CAPA_DIGESTS.get(version, {}).get(wanted)


def download(url: str, dest: Path, expected_sha256: Optional[str]) -> str:
    """Stream `url` to `dest`, return its sha256; raise if it differs from `expected_sha256`."""
    h = hashlib.sha256()
    with _http_get(url, timeout=120) as resp, open(dest, "wb") as out:
        total = int(resp.headers.get("Content-Length") or 0)
        done, last = 0, -1
        for block in iter(lambda: resp.read(1 << 20), b""):
            out.write(block)
            h.update(block)
            done += len(block)
            if total and done * 10 // total != last:
                last = done * 10 // total
                say(f"  {done >> 20} / {total >> 20} MiB")
    digest = h.hexdigest()
    if expected_sha256 and digest != expected_sha256.lower():
        raise SystemExit(f"SHA-256 mismatch for {url}: expected {expected_sha256}, got {digest}")
    return digest


def safe_extract(zip_path: Path, target: Path) -> None:
    """Extract a zip refusing members that would escape `target`."""
    root = target.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            out = (target / member.filename).resolve()
            if root != out and root not in out.parents:
                raise SystemExit(f"Unsafe path in zip: {member.filename}")
        zf.extractall(target)


def find_capa_binary(folder: Path) -> Optional[Path]:
    """The capa executable inside an unzipped release (top level or one level down)."""
    for candidate in (folder / _exe("capa"), *folder.glob(f"*/{_exe('capa')}")):
        if candidate.is_file():
            return candidate
    return None


def capa_version(path: Path) -> Optional[str]:
    """Version string reported by ``capa --version`` or None if it does not run."""
    res = _run([str(path), "--version"], timeout=120)
    if res is None or res.returncode != 0:
        return None
    m = re.search(r"(\d+\.\d+(?:\.\d+)*)", res.stdout + res.stderr)
    return m.group(1) if m else (res.stdout.strip() or None)


def clear_quarantine(path: Path) -> None:
    """Remove com.apple.quarantine (macOS) so Gatekeeper does not block the binary."""
    if platform.system() != "Darwin":
        return
    _run(["xattr", "-dr", "com.apple.quarantine", str(path)])


def installed_capa(dest: Path) -> Optional[Path]:
    folder = dest / "capa"
    return find_capa_binary(folder) if folder.is_dir() else None


def cmd_capa(args: argparse.Namespace) -> int:
    dest = Path(args.dest).expanduser() if args.dest else default_tools_dir()
    version = args.version or PINNED_CAPA_VERSION
    current = installed_capa(dest)
    if current and not args.force:
        have = capa_version(current)
        if have and (version == "latest" or have == version.lstrip("v")):
            msg = f"capa {have} already installed"
            say(msg)
            emit("capa", True, str(current), have, msg)
            return EXIT_OK
    tag, url, expected = resolve_capa_asset(version)
    if args.dry_run:
        msg = f"would download {url} (sha256 {expected or 'not available'}) into {dest / 'capa'}"
        say(msg)
        emit("capa", True, None, tag.lstrip("v"), msg, dry_run=True)
        return EXIT_OK
    if not expected:
        say("WARNING: no sha256 digest available for this asset; the download is NOT verified")
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="capa-install-", dir=dest) as tmp:
        tmp_dir = Path(tmp)
        zip_path = tmp_dir / "capa.zip"
        say(f"Downloading {url}")
        digest = download(url, zip_path, expected)
        say(f"sha256 {digest}" + (" (verified)" if expected else " (unverified)"))
        staging = tmp_dir / "unzipped"
        staging.mkdir()
        safe_extract(zip_path, staging)
        binary = find_capa_binary(staging)
        if binary is None:
            raise SystemExit("The zip does not contain a capa executable")
        final = dest / "capa"
        if final.exists():
            shutil.rmtree(final)
        shutil.move(str(binary.parent if binary.parent != staging else staging), str(final))
    binary = installed_capa(dest)
    if binary is None:
        raise SystemExit(f"capa executable not found in {dest / 'capa'}")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    clear_quarantine(dest / "capa")
    say("Checking the installed binary (the first start unpacks it and can take a minute)...")
    have = capa_version(binary)
    if not have:
        emit("capa", False, str(binary), None,
             "capa was installed but '--version' failed; on macOS check Gatekeeper "
             "(System Settings > Privacy & Security) or run it once from a terminal")
        return EXIT_FAILED
    emit("capa", True, str(binary), have, f"capa {have} installed", sha256=digest)
    return EXIT_OK


# --------------------------------------------------------------------------- radare2
def find_radare2() -> Optional[str]:
    """radare2 on PATH or in the usual install dirs."""
    found = shutil.which("radare2")
    if found:
        return found
    for d in EXTRA_DIRS:
        p = Path(d) / _exe("radare2")
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def radare2_version(path: str) -> Optional[str]:
    res = _run([path, "-v"])
    if res is None:
        return None
    m = re.search(r"radare2\s+(\d+\.\d+(?:\.\d+)*)", res.stdout)
    return m.group(1) if m else None


def radare2_instructions() -> str:
    system = platform.system()
    common = ("radare2 >= 6.0 is required (aflj reports function addresses as 'addr').\n")
    if system == "Darwin":
        return common + "macOS: install Homebrew (https://brew.sh) and run:  brew install radare2"
    if system == "Windows":
        return (common + "Windows: download the release zip from https://github.com/radareorg/radare2/releases "
                "(radare2-<version>-w64.zip), unzip it and add its bin folder to PATH, "
                "or set the 'radare2 Path' option in Ghidra / pass --r2 to mapter_pipeline.py.")
    return (common + "Linux: distribution packages are often older than 6.0. Use one of:\n"
            "  - the official .deb / .tar.xz from https://github.com/radareorg/radare2/releases\n"
            "  - git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh   (installs to /usr/local)\n"
            "  - Homebrew on Linux: brew install radare2\n"
            "Then check:  radare2 -v")


def cmd_radare2(args: argparse.Namespace) -> int:
    min_version = _version_tuple(args.min_version) or MIN_R2_VERSION
    path = find_radare2()
    version = radare2_version(path) if path else None
    if path and version and _version_tuple(version) >= min_version:
        msg = f"radare2 {version} found"
        say(msg)
        emit("radare2", True, path, version, msg)
        return EXIT_OK
    problem = (f"radare2 {version} is older than {'.'.join(map(str, min_version))}" if version
               else "radare2 not found")
    brew = shutil.which("brew") or next((str(Path(d) / "brew") for d in EXTRA_DIRS
                                         if (Path(d) / "brew").is_file()), None)
    if brew:
        installed = _run([brew, "list", "--versions", "radare2"])
        verb = "upgrade" if installed is not None and installed.stdout.strip() else "install"
        cmd = [brew, verb, "radare2"]
        if args.dry_run:
            msg = f"{problem}; would run: {' '.join(cmd)}"
            say(msg)
            emit("radare2", False, path, version, msg, dry_run=True)
            return EXIT_FAILED
        say(f"{problem}; running: {' '.join(cmd)}")
        res = subprocess.run(cmd)
        path = find_radare2()
        version = radare2_version(path) if path else None
        if res.returncode == 0 and path and version and _version_tuple(version) >= min_version:
            emit("radare2", True, path, version, f"radare2 {version} installed with Homebrew")
            return EXIT_OK
        emit("radare2", False, path, version, f"'{' '.join(cmd)}' did not provide radare2 >= "
             f"{'.'.join(map(str, min_version))}")
        return EXIT_FAILED
    instructions = radare2_instructions()
    say(problem)
    say(instructions)
    emit("radare2", False, path, version, f"{problem}. {instructions}", manual=True)
    return EXIT_MANUAL


# --------------------------------------------------------------------------- check
def cmd_check(args: argparse.Namespace) -> int:
    dest = Path(args.dest).expanduser() if args.dest else default_tools_dir()
    capa_path = installed_capa(dest)
    on_path = shutil.which("capa")
    capa_bin = str(capa_path) if capa_path else on_path
    r2 = find_radare2()
    r2_version = radare2_version(r2) if r2 else None
    tools = {
        "capa": {"path": capa_bin, "version": capa_version(Path(capa_bin)) if capa_bin else None,
                 "installed_by_mapter": capa_path is not None},
        "radare2": {"path": r2, "version": r2_version,
                    "ok": bool(r2_version and _version_tuple(r2_version) >= MIN_R2_VERSION)},
    }
    ok = bool(tools["capa"]["version"]) and tools["radare2"]["ok"]
    emit("check", ok, None, None, "all tools present" if ok else "some tools are missing",
         tools=tools, tools_dir=str(dest), platform=f"{platform.system()} {platform.machine()}",
         capa_asset=capa_asset_suffix(), capa_pinned=PINNED_CAPA_VERSION)
    return EXIT_OK if ok else EXIT_FAILED


# --------------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Install the external tools of the MAPTER pipeline.")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("capa", help="download the standalone capa release")
    c.add_argument("--dest", help="tools folder (default: $MAPTER_TOOLS_DIR or ~/.mapter/tools)")
    c.add_argument("--version", help=f"release tag, e.g. v9.4.0, or 'latest' (default {PINNED_CAPA_VERSION})")
    c.add_argument("--force", action="store_true", help="reinstall even if the same version is present")
    c.add_argument("--dry-run", action="store_true", help="report the download without doing it")
    c.set_defaults(func=cmd_capa)
    r = sub.add_parser("radare2", help="check radare2 >= 6 and install it with Homebrew if possible")
    r.add_argument("--dry-run", action="store_true", help="only report what would be done")
    r.add_argument("--min-version", default=".".join(map(str, MIN_R2_VERSION)))
    r.set_defaults(func=cmd_radare2)
    k = sub.add_parser("check", help="JSON report of the installed tools")
    k.add_argument("--dest", help="tools folder to look in")
    k.set_defaults(func=cmd_check)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        return args.func(args)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            say(f"ERROR: {exc.code}")
            emit(args.command, False, None, None, exc.code)
            return EXIT_FAILED
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort report, still one JSON line
        say(f"ERROR: {exc}")
        emit(args.command, False, None, None, f"{type(exc).__name__}: {exc}")
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
