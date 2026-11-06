"""
SAFE function embeddings (radare2 + SAFEtorch) for the MAPTER pipeline.

For every function radare2 finds in a binary this produces one 100-d,
L2-normalised SAFE embedding. Output: one pickle per binary, a DataFrame with

    offset      str    lowercase unpadded hex of the loaded VA, e.g. '0x401000'
    embeddings  list   100 floats
    name        str    radare2 function name (e.g. fcn.00401000)
    size        int    radare2 function size

``DataFrame.attrs`` carries provenance (radare2 version, arch, bits, baddr).

Library use (the model is loaded once per process)::

    safe = SafeTorch(model_dir / "SAFEtorch.pt", model_dir / "word2id.json")
    df = safe.analyze_binary("sample.exe", out_path="sample.pkl", r2_path=None)

CLI::

    python safe_main.py sample.exe other.dll folder/ --out-dir embeddings/ [--model-dir DIR] [--r2 PATH]

Requires radare2 (>= 6 recommended; the older 'offset' aflj key is accepted too)
and the ``r2pipe``, ``torch``, ``numpy`` and ``pandas`` packages.
"""
import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
import torch

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:  # also works under `python -I` / from another cwd
    sys.path.insert(0, str(SCRIPT_DIR))

from safetorch.parameters import Config
from safetorch.safe_network import SAFE
from utils.function_normalizer import FunctionNormalizer
from utils.instructions_converter import InstructionsConverter
from utils.radare_function_analyzer import RadareError, RadareFunctionAnalyzer

logger = logging.getLogger("mapter.safe")

DEFAULT_MODEL_DIR = SCRIPT_DIR / "model"
MODEL_FILE = "SAFEtorch.pt"
VOCAB_FILE = "word2id.json"
MAX_INSTRUCTIONS = 150  # SAFE truncates every function to its first 150 instructions


class NoFunctionsError(RuntimeError):
    """radare2 found no function with a usable embedding in the binary."""


def model_paths(model_dir: Optional[os.PathLike] = None) -> Tuple[Path, Path]:
    """(SAFEtorch.pt, word2id.json) inside `model_dir` (default <script dir>/model)."""
    d = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
    return d / MODEL_FILE, d / VOCAB_FILE


def extract_functions(binary_path, r2_path: Optional[str] = None, depth: int = 0) -> Tuple[Dict[int, dict], dict]:
    """Run radare2 on `binary_path` and return ({address: function record}, info).

    `info` is the radare2 'ij' bin section plus the radare2 version, for provenance.
    Raises RadareError / UnsupportedArchitecture when the binary cannot be analysed.
    """
    with RadareFunctionAnalyzer(str(binary_path), depth=depth, r2_path=r2_path) as analyzer:
        functions = analyzer.analyze()
        info = {"arch": analyzer.arch, "bits": analyzer.bits,
                "baddr": analyzer.info.get("baddr"), "format": analyzer.info.get("bintype")}
        try:
            info["radare2"] = str(analyzer.r2.cmd("?V")).strip()
        except Exception:  # provenance only
            info["radare2"] = None
        logger.info("%s: radare2 found %d functions (%s-%s)", binary_path,
                    analyzer.get_binary_functions(), info["arch"], info["bits"])
    return functions, info


class SafeTorch:
    """The SAFE model plus its token vocabulary; load once, embed many functions."""

    def __init__(self, model_path, instructions_path, device: str = "cpu"):
        self.device = torch.device(device)
        self.model = SAFE(Config())
        state = torch.load(model_path, map_location="cpu", weights_only=True)
        self.model.load_state_dict(state)
        self.model = self.model.to(self.device).eval()
        self.instructions_converter = InstructionsConverter(instructions_path)
        self.function_normalize = FunctionNormalizer(max_instruction=MAX_INSTRUCTIONS)

    @classmethod
    def from_dir(cls, model_dir: Optional[os.PathLike] = None, device: str = "cpu") -> "SafeTorch":
        """Load SAFEtorch.pt and word2id.json from `model_dir` (default <script dir>/model)."""
        model_path, vocab_path = model_paths(model_dir)
        for p in (model_path, vocab_path):
            if not p.is_file():
                raise FileNotFoundError(f"SAFE model file not found: {p}")
        return cls(model_path, vocab_path, device)

    def embed_instructions(self, instructions: List[str]) -> Optional[np.ndarray]:
        """100-d embedding of one function's SAFE tokens (None for an empty function)."""
        if not instructions:
            return None
        converted = self.instructions_converter.convert_to_ids(instructions)
        normalized, length = self.function_normalize.normalize_functions([converted])
        tensor_input = torch.LongTensor(normalized[0]).to(self.device)
        with torch.inference_mode():
            return self.model(tensor_input, length).detach().cpu().numpy()[0]

    def embed_functions(self, functions: Dict[int, dict], binary_label: str = "") -> pd.DataFrame:
        """DataFrame[offset, embeddings, name, size] for the extracted functions.

        Functions with no instructions, an all-zero or a non-finite embedding are skipped.
        """
        rows = []
        for address, fn in functions.items():
            offset = hex(address)
            embedding = self.embed_instructions(fn.get("filtered_instructions") or [])
            if embedding is None:
                logger.debug("not processed %s in %s: no instructions", offset, binary_label)
            elif not np.all(np.isfinite(embedding)) or np.all(embedding == 0):
                logger.debug("degenerate embedding at %s in %s", offset, binary_label)
            else:
                size = fn.get("size")
                rows.append((offset, embedding.tolist(), fn.get("name"),
                             size if size is not None else np.nan))
        df = pd.DataFrame(rows, columns=["offset", "embeddings", "name", "size"])
        df["size"] = pd.to_numeric(df["size"])  # int when complete, float with NaN otherwise
        return df

    def analyze_binary(self, binary_path, out_path=None, r2_path: Optional[str] = None) -> pd.DataFrame:
        """Embed every function of one binary; writes the pickle when `out_path` is given.

        Raises NoFunctionsError when nothing could be embedded.
        """
        functions, info = extract_functions(binary_path, r2_path)
        df = self.embed_functions(functions, str(binary_path))
        if df.empty:
            raise NoFunctionsError("radare2 found no function with a usable embedding")
        df.attrs.update(info)
        if out_path is not None:
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)
            df.to_pickle(out_path)
        return df


def embed_binary_to_pickle(binary_path, out_pkl, model_dir=None, r2_path: Optional[str] = None) -> int:
    """Whole SAFE step for one binary, used by pipeline.safe_stage in a child process.

    radare2 runs first so an unsupported or unreadable binary fails fast, before the
    220 MB model is loaded. The pickle is written atomically. Returns the number of
    functions embedded.
    """
    functions, info = extract_functions(binary_path, r2_path)
    if not any(fn.get("filtered_instructions") for fn in functions.values()):
        raise NoFunctionsError("radare2 found no function with instructions")
    safe = SafeTorch.from_dir(model_dir)
    df = safe.embed_functions(functions, str(binary_path))
    if df.empty:
        raise NoFunctionsError("no function produced a usable embedding")
    df.attrs.update(info)
    out_pkl = Path(out_pkl)
    out_pkl.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_pkl.with_name(out_pkl.name + ".tmp")
    df.to_pickle(tmp)
    os.replace(tmp, out_pkl)
    return len(df)


# --------------------------------------------------------------------------- CLI
def _collect_inputs(paths: Iterable[str], recursive: bool) -> List[Path]:
    files: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            it = p.rglob("*") if recursive else p.iterdir()
            files.extend(sorted(f for f in it if f.is_file() and not f.name.startswith(".")))
        elif p.is_file():
            files.append(p)
        else:
            logger.warning("not found: %s", p)
    return files


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="SAFE function embeddings with radare2 + SAFEtorch.")
    ap.add_argument("inputs", nargs="+", help="binary files and/or directories of binaries")
    ap.add_argument("--out-dir", required=True, help="where <binary file name>.pkl are written")
    ap.add_argument("--model-dir", default=str(DEFAULT_MODEL_DIR),
                    help="folder with SAFEtorch.pt and word2id.json (default: <script dir>/model)")
    ap.add_argument("--r2", default=None, help="path to the radare2 executable (default: PATH)")
    ap.add_argument("--recursive", action="store_true", help="descend into input directories")
    ap.add_argument("--force", action="store_true", help="recompute existing outputs")
    ap.add_argument("--threads", type=int, default=0, help="torch CPU threads (default: torch's)")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    if args.threads > 0:
        torch.set_num_threads(args.threads)
    files = _collect_inputs(args.inputs, args.recursive)
    if not files:
        logger.error("no input binaries")
        return 2
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        safe = SafeTorch.from_dir(args.model_dir)  # loaded once for all binaries
    except FileNotFoundError as e:
        logger.error("%s", e)
        return 2

    failed = 0
    for binary in files:
        out_pkl = out_dir / (binary.name + ".pkl")
        if out_pkl.exists() and out_pkl.stat().st_size > 0 and not args.force:
            logger.info("skip (exists): %s", out_pkl)
            continue
        try:
            df = safe.analyze_binary(binary, out_path=out_pkl, r2_path=args.r2)
            logger.info("%s: %d embeddings -> %s", binary, len(df), out_pkl)
        except (RadareError, NoFunctionsError) as e:
            logger.error("%s: %s", binary, e)
            failed += 1
        except Exception:
            logger.exception("%s: unexpected error", binary)
            failed += 1
    logger.info("done: %d ok, %d failed", len(files) - failed, failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
