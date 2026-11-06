# MAPTER for Ghidra

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24011199.svg)](https://doi.org/10.5281/zenodo.24011199)

**MAPTER** maps the functions of a set of binaries (e.g. the samples of an APT
group) onto a 2D plane using SAFE function embeddings, groups the binaries by
how many functions they share, and links that map to Ghidra:

- click a point in the map → Ghidra opens the binary and jumps to the function;
- move the cursor in Ghidra → the map rings the function and switches to its
  cluster;
- generate the map for your own binaries from Ghidra (radare2 + SAFE, CAPA,
  AVClass2, dimensionality reduction).

The repository contains the Ghidra extension **MapterBridge**, the MAPTER web
app (Dash) it launches, the generation pipeline, and an APT 19 sample dataset.

## Install (users)

1. Download the extension zip for your Ghidra version from the
   [Releases](../../releases) page
   (`ghidra_<version>_PUBLIC_<date>_MapterBridge.zip`; Ghidra 11.3.2 and 12.0
   are provided). It already contains the web app, the pipeline and the SAFE
   model.
2. Ghidra: **File → Install Extensions → +**, pick the zip, restart Ghidra,
   and enable **MapterBridgePlugin** when the CodeBrowser asks (or **File →
   Configure → Miscellaneous**).
3. **Tools → MAPTER → Open MAPTER.** The first time, the Python Environment
   dialog helps you pick or create a Python with the app's packages.

Full guide and reference (usage, options, HTTP API, troubleshooting):
[GHIDRA_INTEGRATION_README.md](GHIDRA_INTEGRATION_README.md).

Requirements: Ghidra 11.3+ with Java 21, Python 3.9+ (the app and the
pipeline use separate virtual environments, both created from Ghidra), and
for generating new maps radare2 ≥ 6 (capa is optional and can be installed
from the pipeline dialog).

## Repository layout

| Path | What |
| --- | --- |
| `MapterBridge/` | Ghidra extension (Java): navigation server, Follow Ghidra, app launcher, pipeline launcher |
| `app.py`, `*.py`, `assets/` | MAPTER web app (Dash) bundled into the extension |
| `MAPTER_backend/` | Generation pipeline (`mapter_pipeline.py`): SAFE embeddings, CAPA, AVClass2, reduction, merge. See [MAPTER_backend/README.md](MAPTER_backend/README.md) |
| `datasets/` | Data folder format ([datasets/README.md](datasets/README.md)) and the APT 19 sample |

## Build from source

You need JDK 21+, Gradle 8.5+, a Ghidra installation per target version, and
the SAFE model, which is not stored in git (GitHub limits files to 100 MB):

```bash
# 1. SAFE model -> MAPTER_backend/model/ (checksum-verified)
python3 MAPTER_backend/tools/fetch_model.py \
    --url https://github.com/0x4l3x/MAPTER-Ghidra/releases/download/v1.0.1/safe-model.zip

# 2. Build one zip per Ghidra version (output in MapterBridge/dist/)
cd MapterBridge
export JAVA_HOME=$(/usr/libexec/java_home -v 21)   # macOS; any JDK 21+ elsewhere
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra_11.3.2_PUBLIC
```

The build copies the web app, the pipeline, the model and the APT 19 sample
into the zip (the lists are in `MapterBridge/build.gradle`); rebuild after
changing any of them.

Run the web app without Ghidra:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-app.txt
.venv/bin/python app.py          # http://localhost:15510
```

Run the pipeline without Ghidra: see
[MAPTER_backend/README.md](MAPTER_backend/README.md).

## Citing

If you use MAPTER for Ghidra, please cite the archived release
([CITATION.cff](CITATION.cff) has the full metadata; GitHub's "Cite this
repository" button exports it):

```bibtex
@software{mapter_ghidra,
  author    = {Barreiro-Morante, Alejandro and Blasco Al{\'i}s, Jorge},
  title     = {{MAPTER} for {Ghidra}},
  year      = {2026},
  publisher = {Zenodo},
  version   = {v1.0.1},
  doi       = {10.5281/zenodo.24011199},
  url       = {https://doi.org/10.5281/zenodo.24011199},
}
```

The DOI above always resolves to the latest version; v1.0.1 specifically is
[10.5281/zenodo.24011200](https://doi.org/10.5281/zenodo.24011200).

## License

MIT — see [LICENSE](LICENSE). The SAFE network code and model come from
SAFEtorch (MIT, Copyright Facebook, Inc. and its affiliates); see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Tools used at run time
(Ghidra, radare2, capa, AVClass2 and the Python packages) are installed
separately and keep their own licenses.
