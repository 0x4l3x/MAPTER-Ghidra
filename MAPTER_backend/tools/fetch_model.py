#!/usr/bin/env python3
"""
fetch_model.py — download the SAFE model into MAPTER_backend/model/.

The model (SAFEtorch.pt ~220 MB + word2id.json) is too large for a git
repository, so it is published as a GitHub Release asset (``safe-model.zip``).
It is only needed to build the Ghidra extension from source or to run the
pipeline from a clone; the released extension zips already contain it.

Usage:
    python tools/fetch_model.py --url https://github.com/<owner>/<repo>/releases/download/<tag>/safe-model.zip
    python tools/fetch_model.py --zip /path/to/safe-model.zip     # offline
    MAPTER_MODEL_URL=<url> python tools/fetch_model.py

Both files are checked against the SHA-256 values below; nothing is installed
outside the model folder. Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

logger = logging.getLogger("mapter.fetch_model")

MODEL_DIR = Path(__file__).resolve().parent.parent / "model"
# SHA-256 of the published model files (SAFEtorch model, MIT, see THIRD_PARTY_NOTICES.md).
EXPECTED = {
    "SAFEtorch.pt": "c0e2f37b61fdca404fb6b945f29d40b53342a14247c46b935f1c21d3776dbdd9",
    "word2id.json": "a41c8f667f31d83fcd2c3753eb319bfb2bd5d8690320b36251c428b84bf88380",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def model_ok(folder: Path) -> bool:
    return all((folder / n).is_file() and sha256(folder / n) == d for n, d in EXPECTED.items())


def install_from_zip(archive: Path, dest: Path) -> None:
    """Extract the two model files (by base name, so no path traversal) and verify them."""
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        members = {Path(m).name: m for m in zf.namelist() if Path(m).name in EXPECTED}
        missing = set(EXPECTED) - set(members)
        if missing:
            raise SystemExit(f"{archive} lacks {sorted(missing)}")
        for name, member in members.items():
            tmp = dest / (name + ".part")
            with zf.open(member) as src, open(tmp, "wb") as out:
                shutil.copyfileobj(src, out)
            if sha256(tmp) != EXPECTED[name]:
                tmp.unlink()
                raise SystemExit(f"checksum mismatch for {name}: wrong or corrupted archive")
            os.replace(tmp, dest / name)
            logger.info(f"installed {dest / name}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--url", default=os.environ.get("MAPTER_MODEL_URL"), help="URL of safe-model.zip")
    src.add_argument("--zip", type=Path, help="local safe-model.zip")
    ap.add_argument("--dest", type=Path, default=MODEL_DIR, help=f"model folder (default {MODEL_DIR})")
    ap.add_argument("--force", action="store_true", help="download even if a valid model is present")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not args.force and model_ok(args.dest):
        logger.info(f"SAFE model already present and verified in {args.dest}")
        return 0
    if args.zip:
        install_from_zip(args.zip, args.dest)
    elif args.url:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "safe-model.zip"
            logger.info(f"downloading {args.url} ...")
            urllib.request.urlretrieve(args.url, archive)
            install_from_zip(archive, args.dest)
    else:
        ap.error("give --url (the GitHub Release asset safe-model.zip) or --zip")
    return 0 if model_ok(args.dest) else 1


if __name__ == "__main__":
    sys.exit(main())
