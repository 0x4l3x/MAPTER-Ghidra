"""
Dataset registry for the MAPTER visualizer
==========================================
Finds MAPTER data folders on disk and hands the Dash app a ready-to-use data
processor for each. This is the data contract between the app and whatever
produces the data (today the research notebooks, later the MAPTER generation
pipeline: SAFE embeddings + CAPA + dimensionality reduction).

Where the data comes from
-------------------------
- ``MAPTER_DATA`` set (Ghidra's MapterBridge passes the folder chosen for the
  current Ghidra project): that single folder is the only dataset.
- Otherwise every subfolder of ``<app>/datasets`` that has a ``reduced.pkl``.
  When MapterBridge launches the app without a folder (``MAPTER_MANAGED=1``),
  this is the bundled sample data.

A MAPTER data folder
--------------------
::

    <folder>/
      reduced.pkl      # REQUIRED  per-function 2D map
      avclass.pkl      # optional  per-binary family labels
      capa/            # optional  CAPA JSON results, one file per binary
      dataset.json     # optional  metadata (display name, default thresholds)

``reduced.pkl`` must be a pandas DataFrame with (at least) these columns::

    binary_name  offset  name  size  x  y

- ``binary_name`` : str, identifies the binary (e.g. a truncated hash); the
                    Ghidra program name must start with / contain it.
- ``offset``      : str hex address, e.g. "0x401000" (the loaded VA; used by
                    the Ghidra navigation link as-is).
- ``name``        : str, function name/label.
- ``size``        : numeric, function size.
- ``x``, ``y``    : float, the 2D embedding coordinates to plot.

``avclass.pkl`` must be a DataFrame with ``binary_name`` and ``label`` columns;
extra columns are ignored. If ``avclass_apt_group`` is set in dataset.json and
the table has an ``apt_group`` column, it is filtered to that group first.

``dataset.json`` (all keys optional)::

    {
      "id": "APT_21",                     # defaults to the folder name
      "name": "APT 21",                   # display name; defaults to the id
      "description": "APT21 malware ...",
      "reduced": "reduced.pkl",           # file names, relative to the folder
      "avclass": "avclass.pkl",
      "avclass_apt_group": "APT_21",
      "default_function_threshold": 5.0,  # δ, neighbour radius
      "default_binary_threshold": 0.2,    # min. shared functions (fraction)
      "default_distance_threshold": 0.75, # dendrogram cut height
      "avclass_threshold": 0.9
    }

For older layouts, CAPA results are also read from ``<parent>/capa/<id>``.
"""

import json
import logging
import os
from typing import Dict, List, Optional

import pandas as pd

from data_processor import DataProcessor
from malware_data_loader import CapaLoader

logger = logging.getLogger(__name__)

# Columns every reduced.pkl must provide for the app to work.
REQUIRED_REDUCED_COLUMNS = ["binary_name", "offset", "name", "size", "x", "y"]

# A reduced.pkl carrying any of these is already CAPA-enriched (written by
# mapter_pipeline.py), so the capa/ folder is not merged again.
_CAPA_COLUMNS = {"rule_name", "library_name"}

# Default location of the datasets root, resolved relative to this file so the
# app works regardless of the current working directory.
DEFAULT_DATASETS_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datasets")


class ManifestDataProcessor(DataProcessor):
    """A DataProcessor that loads a MAPTER data folder (see the module doc).

    Reuses every clustering/stats method of DataProcessor; only load_data is
    specific to the folder layout.
    """

    def __init__(self, manifest: Dict, dataset_dir: str):
        super().__init__()
        self.manifest = manifest
        self.dataset_dir = dataset_dir
        self.apt_group = manifest.get("id") or os.path.basename(dataset_dir)
        # Self-contained <folder>/capa, else the older <parent>/capa/<id> layout.
        self.capa_dir = os.path.join(dataset_dir, "capa")
        if not os.path.isdir(self.capa_dir):
            self.capa_dir = os.path.join(os.path.dirname(dataset_dir), "capa", self.apt_group)

    def load_data(self) -> Optional[pd.DataFrame]:
        """Load reduced embeddings (+ optional avclass labels) from the manifest."""
        reduced_rel = self.manifest.get("reduced", "reduced.pkl")
        reduced_path = os.path.join(self.dataset_dir, reduced_rel)
        if not os.path.exists(reduced_path):
            logger.error(f"Reduced pickle not found: {reduced_path}")
            return None

        try:
            df = pd.read_pickle(reduced_path)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Failed to read {reduced_path}: {exc}")
            return None

        missing = [c for c in REQUIRED_REDUCED_COLUMNS if c not in df.columns]
        if missing:
            logger.error(f"{reduced_path} is missing required "
                         f"columns {missing}; found {list(df.columns)}")
            return None

        df = df.infer_objects(copy=False).fillna({"size": 0})

        # Optional AVClass labels (avclass.pkl, else the avclass_label column).
        self.avclass_tags = self._load_avclass(df)

        # Optional CAPA enrichment (rule_name, library_name, ... columns). The
        # merge is a left join on (binary_name, offset): one row per function.
        # Enriched pickles (written by mapter_pipeline.py) already carry the
        # CAPA columns, so there is nothing to merge.
        if _CAPA_COLUMNS.intersection(df.columns):
            logger.info("reduced pickle already contains CAPA columns; "
                        "skipping CAPA merge")
        elif os.path.isdir(self.capa_dir):
            logger.info(f"Loading CAPA data from {self.capa_dir}")
            try:
                capa_loader = CapaLoader(self.capa_dir)
                capa_dataframes = capa_loader.load_capa_data()
                df = capa_loader.merge_capa_with_df(df, capa_dataframes)
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"Ignoring CAPA data in {self.capa_dir}: {exc}")
        else:
            logger.info(f"No CAPA data found at {self.capa_dir}")

        # Set only now so the app sees the CAPA columns too.
        self.data = df
        n_bins = df["binary_name"].nunique()
        logger.info(f"Loaded {len(df)} functions from {n_bins} "
                    f"binaries for dataset '{self.apt_group}'")
        return self.data

    @staticmethod
    def _avclass_from_column(data: pd.DataFrame) -> Dict[str, str]:
        """{binary_name: first non-null avclass_label} from an enriched pickle."""
        if "avclass_label" not in data.columns:
            return {}
        sub = data[["binary_name", "avclass_label"]].dropna()
        first = sub.groupby("binary_name", sort=False)["avclass_label"].first()
        return {str(k): v for k, v in first.items()}

    def _load_avclass(self, data: pd.DataFrame) -> Dict[str, str]:
        """AVClass tags: avclass.pkl when present (backward compatible), else
        the ``avclass_label`` column of reduced.pkl."""
        avclass_rel = self.manifest.get("avclass")
        if not avclass_rel:
            return self._avclass_from_column(data)
        avclass_path = os.path.join(self.dataset_dir, avclass_rel)
        if not os.path.exists(avclass_path):
            if "avclass_label" in data.columns:
                return self._avclass_from_column(data)
            logger.warning(f"avclass file not found: {avclass_path}")
            return {}
        try:
            av = pd.read_pickle(avclass_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Failed to read {avclass_path}: {exc}")
            return {}

        group = self.manifest.get("avclass_apt_group")
        if group and "apt_group" in av.columns:
            av = av[av["apt_group"] == group].copy()

        if "binary_name" not in av.columns or "label" not in av.columns:
            logger.warning(f"avclass table needs 'binary_name' and "
                           f"'label' columns; found {list(av.columns)}")
            return {}

        # Restrict to binaries actually present in the embeddings.
        present = set(data["binary_name"].unique())
        av = av[av["binary_name"].isin(present)]
        return {row["binary_name"]: row["label"] for _, row in av.iterrows()}


# ---------------------------------------------------------------------------
# Discovery + warmed-processor cache
# ---------------------------------------------------------------------------
# The Dash callbacks are stateless at the callback level: they carry only the
# dataset id and re-fetch a processor here. DataProcessor is stateful across
# method calls (load_data populates instance attrs that later getters read), so
# we memoize one warmed (already load_data()-ed) processor per dataset id.
_PROCESSOR_CACHE: Dict[str, ManifestDataProcessor] = {}


def _read_manifest(dataset_dir: str) -> Optional[Dict]:
    """Manifest of a MAPTER data folder: dataset.json (optional) completed with
    the folder conventions; None if the folder has no reduced pickle."""
    manifest: Dict = {}
    manifest_path = os.path.join(dataset_dir, "dataset.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(f"Ignoring bad manifest {manifest_path}: {exc}")
            manifest = {}
    manifest.setdefault("reduced", "reduced.pkl")
    if not os.path.exists(os.path.join(dataset_dir, manifest["reduced"])):
        return None
    if "avclass" not in manifest and os.path.exists(os.path.join(dataset_dir, "avclass.pkl")):
        manifest["avclass"] = "avclass.pkl"
    manifest.setdefault("id", os.path.basename(os.path.normpath(dataset_dir)))
    manifest.setdefault("name", manifest["id"])
    manifest["_dir"] = dataset_dir
    return manifest


def _dataset_dirs(root: Optional[str] = None) -> Dict[str, str]:
    """{dataset id: folder} for every dataset the app can show (see module doc)."""
    folders: List[str] = []
    data = os.environ.get("MAPTER_DATA")
    if data and root is None:
        folders = [data]
    else:
        root = root or DEFAULT_DATASETS_ROOT
        if not os.path.isdir(root):
            logger.warning(f"Datasets root does not exist: {root}")
            return {}
        folders = [os.path.join(root, e) for e in sorted(os.listdir(root))]
    out: Dict[str, str] = {}
    for folder in folders:
        if os.path.isdir(folder):
            manifest = _read_manifest(folder)
            if manifest is not None:
                out.setdefault(manifest["id"], folder)
            elif data and root is None:
                logger.error(f"MAPTER data folder has no reduced.pkl: {folder}")
    return out


def data_source() -> Dict:
    """How the app got its data, for the UI: managed by Ghidra or not, sample
    data or the folder chosen for the Ghidra project."""
    managed = os.environ.get("MAPTER_MANAGED") == "1"
    folder = os.environ.get("MAPTER_DATA")
    return {"managed": managed, "folder": folder, "sample": managed and not folder}


def list_datasets(root: Optional[str] = None) -> List[Dict]:
    """Datasets the app can show, as {id, name, description, folder} dicts sorted
    by name."""
    out: List[Dict] = []
    for dataset_id, folder in _dataset_dirs(root).items():
        manifest = _read_manifest(folder) or {}
        out.append({
            "id": dataset_id,
            "name": manifest.get("name", dataset_id),
            "description": manifest.get("description", ""),
            "folder": folder,
        })
    return sorted(out, key=lambda d: d["name"])


def get_processor(dataset_id: str, root: Optional[str] = None) -> Optional[ManifestDataProcessor]:
    """Return a warmed (load_data()-ed) processor for ``dataset_id``.

    Memoized: repeated calls for the same id return the same warmed instance, so
    re-fetching inside any callback is cheap. Returns None if the dataset can't
    be found or loaded.
    """
    if dataset_id in _PROCESSOR_CACHE:
        return _PROCESSOR_CACHE[dataset_id]

    dataset_dir = _dataset_dirs(root).get(dataset_id)
    manifest = _read_manifest(dataset_dir) if dataset_dir else None
    if manifest is None:
        logger.error(f"No MAPTER data for dataset id '{dataset_id}'")
        return None

    processor = ManifestDataProcessor(manifest, dataset_dir)
    if processor.load_data() is None:
        return None

    _PROCESSOR_CACHE[dataset_id] = processor
    return processor


def get_manifest(dataset_id: str, root: Optional[str] = None) -> Dict:
    """Return the manifest dict for a dataset (or {} if not found).

    Used by the app to read optional per-dataset settings such as
    default_function_threshold, default_binary_threshold,
    default_distance_threshold and avclass_threshold.
    """
    dataset_dir = _dataset_dirs(root).get(dataset_id) if dataset_id else None
    return (_read_manifest(dataset_dir) if dataset_dir else None) or {}


def get_columns(dataset_id: str, root: Optional[str] = None) -> List[str]:
    """Return the columns present in a dataset's reduced DataFrame.

    Used by the UI to show only the filters a dataset can actually support
    (e.g. hide CAPA-rule filters when the dataset has no 'rule_name' column).
    Returns [] if the dataset can't be loaded.
    """
    processor = get_processor(dataset_id, root)
    if processor is None or processor.data is None:
        return []
    return list(processor.data.columns)


def clear_cache() -> None:
    """Drop all cached processors (e.g. after datasets change on disk)."""
    _PROCESSOR_CACHE.clear()
