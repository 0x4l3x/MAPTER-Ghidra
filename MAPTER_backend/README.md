# MAPTER backend: the generation pipeline

`mapter_pipeline.py` turns **a folder of binaries** (or the programs of a Ghidra
project) into a **MAPTER data folder** that the Dash app loads
(layout: [`../datasets/README.md`](../datasets/README.md)).

```
binaries ──▶ safe ──▶ capa ──▶ avclass ──▶ reduce ──▶ merge ──▶ data folder
            radare2   capa    AVClass2    t-SNE /     one       reduced.pkl
            + SAFE            (VirusTotal UMAP /      enriched  dataset.json
            embeddings         reports)   PCA         pickle    binaries.json
                                                                capa/ avclass.pkl
```

It is a command-line program first. Ghidra only exports the project's original
binaries and starts the same CLI (see [Running from Ghidra](#running-from-ghidra)).

## Stages

| Stage | Tool | Input | Output (in the work folder) |
| --- | --- | --- | --- |
| `safe` | radare2 (via `r2pipe`) + SAFE GRU network (torch, CPU) | `binaries/<sha256>` | `embeddings/<sha256>.pkl`: one row per function (`offset`, 100-d `embeddings`, `name`, `size`) |
| `capa` | capa standalone binary + `capa_simplifier.py` | `binaries/<sha256>` | `capa_raw/<sha256>.json`, simplified `capa/<sha256>.json` |
| `avclass` | AVClass2 (`avclass-malicialab`) on VirusTotal reports | `vt_reports/<sha256>.json` | `avclass.pkl` |
| `reduce` | `mapter.py` (standardise, PCA, t-SNE / UMAP / PCA) | `embeddings/` | `reduced_raw.pkl` |
| `merge` | `pipeline/merge_stage.py` | everything above | the data folder |

* `capa` and `avclass` are **optional**: if capa or avclass is not installed, or
  there are no VirusTotal reports, the stage is skipped with a warning and the
  map is still produced (without those columns).
* A binary that fails a stage (unsupported format, timeout, ...) is recorded in
  `status.json` and the log; it does not stop the run. A run only fails when
  nothing can be produced.
* **Resumable:** every per-binary output is written atomically and skipped on a
  rerun. `--force` ignores previous outputs.

### Binary key

Every binary is identified by its **sha256**. Files in `binaries/` are named by
the full sha256 (no extension). `binary_name`, the key used by the app, its CAPA
join and the Ghidra program matcher, is the first 6 hex characters of the
sha256 (lengthened for the whole run only if two binaries share the prefix).
`binaries.json` maps each `binary_name` back to the sha256, the Ghidra program
name and the original path. File names never act as keys.

### Work folder

```
<work>/
  manifest.json            binaries to process (written by the CLI or by Ghidra)
  binaries/<sha256>        input files
  embeddings/  capa_raw/  capa/  vt_reports/  avclass.pkl  reduced_raw.pkl
  data_folder/             final result (default --out)
  status.json              live progress: state running|done|failed|cancelled
  pipeline.log             log
  pipeline.lock            pid of the active run (a second run is refused)
```

### Output = the MAPTER data folder

```
data_folder/
  reduced.pkl     x, y, binary_name, offset, name, size, sha256
                  + CAPA columns: rule_name, tactic, technique, subtechnique,
                    attack_id, objective, behavior, method, mbc_id, library_name
                  + avclass_label
  dataset.json    id, name, method, counts, default thresholds
  binaries.json   binary_name -> {sha256, program_name, domain_path, path}
  capa/<sha256>.json   simplified CAPA reports (provenance)
  avclass.pkl          binary_name, label, ... (provenance)
```

`offset` is the loaded virtual address as lowercase unpadded hex (`0x401000`);
`x`, `y` are float32. The app reads the CAPA and avclass columns directly from
`reduced.pkl` when they are present; multiple CAPA values of one function are
joined with `; `.

## Installation

The pipeline runs in **its own Python environment**, separate from the Dash
app's (torch is large and the app does not need it). The original SAFE pins
(torch 1.4, numpy 1.18) are **not** needed: the model loads on current torch.

### 1. Python environment

```bash
cd MAPTER_backend
python3 -m venv mapter-pipeline-venv
mapter-pipeline-venv/bin/pip install -r requirements-pipeline.txt
mapter-pipeline-venv/bin/python mapter_pipeline.py --check
```

Python 3.9 or newer. Packages: torch (CPU is enough), numpy, pandas,
scikit-learn, `r2pipe`, `avclass-malicialab`, tqdm, requests. UMAP is optional:
uncomment `umap-learn` in the requirements file (pulls numba). From Ghidra use
**Run MAPTER Pipeline... > Python Environment...**, which does this for you
(default folder `mapter-pipeline-venv` in Ghidra's settings folder).

### 2. radare2 (>= 6.0, required)

radare2 6 reports function addresses as `addr`; older releases do not work.

* **macOS:** `brew install radare2` (or `python tools/install_tools.py radare2`).
* **Linux:** distribution packages are often older than 6.0. Use the official
  `.deb` / `.tar.xz` from <https://github.com/radareorg/radare2/releases>, or
  `git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh`
  (installs to `/usr/local`), or Homebrew on Linux.
* **Windows:** download the release zip from the same releases page, unzip it
  and add its `bin` folder to `PATH` (or pass `--r2 C:\...\radare2.exe`).

Check with `radare2 -v`. A GUI-launched Ghidra has a minimal `PATH`; the
pipeline also looks in `/opt/homebrew/bin`, `/usr/local/bin` and
`~/.local/bin`, or you can set the **radare2 Path** option in Ghidra.

### 3. capa (optional, recommended)

```bash
python tools/install_tools.py capa            # -> ~/.mapter/tools/capa/capa
python tools/install_tools.py capa --dest DIR --version v9.4.0
```

Downloads the standalone release for your platform (rules and signatures are
embedded) from <https://github.com/mandiant/capa/releases>, verifies the SHA-256
digest published by the GitHub API, unzips it, marks it executable and removes
the macOS quarantine flag. The tools folder is `$MAPTER_TOOLS_DIR` or
`~/.mapter/tools`, the same for the CLI and for Ghidra (every version). You can
also point to any capa with `--capa PATH`. `python tools/install_tools.py check`
prints what is installed. `capa` installed with `pip install flare-capa` needs
rules passed separately and is **not** supported; use the standalone binary.

Known limits: .NET samples and shellcode get no CAPA columns; capa and radare2
discover different function sets, so only the capa hits that fall on a radare2
function entry reach the map.

### 4. AVClass2 and VirusTotal (optional)

`avclass-malicialab` is installed by `requirements-pipeline.txt`
(`pip install avclass-malicialab`). It labels samples from **VirusTotal v3 file
reports**. Two ways to provide them:

* `--vt-reports DIR`: reports you already have, one JSON file per sample named
  `<sha256>.json`.
* `--vt-fetch`: look the hashes up on VirusTotal (key in the environment
  variable `VT_API_KEY`, never on the command line, never written to disk or
  to the log).

A **free** VirusTotal key is limited to **4 requests/minute and 500/day**; the
fetcher waits 15 s between requests, backs off on HTTP 429 and resumes on the
next run (about 500 binaries per day). Only hashes are looked up: **samples are
never uploaded**. Hashes VirusTotal does not know (HTTP 404) simply get no
label (`Unknown` in the app). `vt_fetch.py` is also a standalone CLI:
`VT_API_KEY=... python vt_fetch.py --out reports/ --binaries folder/`.

The label of a binary is the first `FAM:`/`UNK:` tag of AVClass's ranked
description, `None` if there is none and `-` if no engine labelled it.

## Usage

```bash
PY=mapter-pipeline-venv/bin/python

# prerequisites report (JSON); exit 0 when the required parts are present
$PY mapter_pipeline.py --check

# a folder of binaries -> data folder
$PY mapter_pipeline.py --work ~/mapter-work/apt1 --binaries ~/samples/apt1 --name "APT 1"

# resume after an interruption: same command (finished binaries are skipped)
# redo everything:
$PY mapter_pipeline.py --work ~/mapter-work/apt1 --binaries ~/samples/apt1 --force

# only some stages, e.g. recompute the map with another method
$PY mapter_pipeline.py --work ~/mapter-work/apt1 --stages reduce,merge --method umap

# with AVClass labels from VirusTotal (free key) or from existing reports
VT_API_KEY=... $PY mapter_pipeline.py --work W --binaries DIR --vt-fetch
$PY mapter_pipeline.py --work W --binaries DIR --vt-reports ~/vt_reports

# explicit tool paths, more parallelism, longer timeouts
$PY mapter_pipeline.py --work W --binaries DIR --r2 /opt/homebrew/bin/radare2 \
    --capa ~/.mapter/tools/capa/capa --workers 8 --r2-timeout 3600
```

| Option | Meaning |
| --- | --- |
| `--work DIR` | work folder (required) |
| `--binaries DIR` / `--manifest FILE` | input: hash and copy every regular file of a folder, or a manifest written by Ghidra (default `<work>/manifest.json`) |
| `--out DIR` | data folder (default `<work>/data_folder`) |
| `--name NAME` | dataset display name |
| `--stages LIST` | subset of `safe,capa,avclass,reduce,merge` |
| `--method` | `tsne` (default), `umap`, `pca`, `fixed` |
| `--model-dir DIR` | folder with `SAFEtorch.pt` and `word2id.json` (default `model/` here) |
| `--r2 PATH`, `--capa PATH` | tool paths (else `PATH`, `$MAPTER_TOOLS_DIR`, Homebrew dirs) |
| `--vt-reports DIR`, `--vt-fetch` | AVClass input |
| `--workers N` | parallel binaries (SAFE and capa) |
| `--r2-timeout S`, `--capa-timeout S` | per-binary time limits (default 1800 / 3600; capa with vivisect often needs 5-20 min per binary) |
| `--app-dir DIR` | Dash app folder, to compute the default δ with `recommend_delta.py` |
| `--force` | ignore previous outputs |
| `--check` | prerequisite report, then exit |
| `-v` | debug logging |

Exit codes: `0` done, `1` failed, `2` cancelled. `SIGTERM`/`Ctrl-C` finish the
current binary and set state `cancelled`; a second signal stops at once. The
process calls `setsid()` where available, so it survives the program that
started it.

### Reduction methods

`mapter.py` (also a CLI) replaces the GPU-only original. Default **`tsne`**:
standardise, PCA to 95 % of the variance (at most 50 dimensions), then a t-SNE
over a few perplexities, keeping the best by a composite quality score
(neighbourhood preservation, distance correlation, outlier penalty). Inputs
with few functions use adaptive settings and always produce a valid map.
Coordinates are rescaled so the 99th percentile of |x|, |y| is about 100, the
scale the app's default thresholds assume. cuML/cupy are used only if
importable. `umap` needs `umap-learn`; `pca` is fast and rough; `fixed` is
the original MAPTER recipe (PCA 40, t-SNE perplexity 50, seed 1312).
t-SNE and UMAP are not incremental: adding a binary means rerunning
`reduce,merge` (SAFE and capa results are reused).

## Running from Ghidra

**Tools > MAPTER > Run MAPTER Pipeline...** (MapterBridge). It exports the
project's *original* binaries (the imported file bytes, checked against the
program's `Executable SHA256`), then starts this CLI as a detached process and
shows its progress from `status.json`. On success the project's **MAPTER Data
Folder** is set to the output. Options (Edit > Tool Options > MAPTER Bridge):
*MAPTER Backend Folder*, *SAFE Model Folder*, *radare2 Path*, *capa Path*,
*Pipeline Python Environment*. The extension bundles this folder (without
`model/`) under `data/mapter_backend`. Details:
[`../GHIDRA_INTEGRATION_README.md`](../GHIDRA_INTEGRATION_README.md).

## Troubleshooting

* **`--check` says radare2 is missing / too old:** install >= 6.0 (above) or pass
  `--r2`. `radare2 -v` must print 6.x.
* **`No module named torch` (or r2pipe, ...):** the command ran in the wrong
  Python. Use the pipeline environment's interpreter.
* **Model files missing:** `SAFEtorch.pt` (~220 MB) and `word2id.json` live in
  `model/` (also bundled in the Ghidra extension). Point `--model-dir` /
  *SAFE Model Folder* at a folder that has both, or leave the option empty.
* **A binary has no functions / is skipped:** SAFE handles x86 and ARM; other
  architectures give empty results. Look in `pipeline.log` and `status.json`.
* **radare2 is slow:** `aaa` can take long on big binaries; raise
  `--r2-timeout`, lower `--workers` if memory is short.
* **capa fails on some files:** unsupported formats (exit codes 14-18) are
  per-binary failures, not fatal. macOS may block the downloaded binary:
  run `xattr -dr com.apple.quarantine <capa folder>` (the installer does).
* **No avclass labels:** no reports were found (`--vt-reports`/`--vt-fetch`),
  `avclass-malicialab` is not installed, or VirusTotal does not know the hashes.
* **"Another run holds the lock":** a live pipeline uses that work folder; wait
  or cancel it. A stale `pipeline.lock` of a dead process is ignored.
* **Ghidra does not jump to the function (PIE ELF / shared objects):**
  radare2 and Ghidra may use different base addresses for those; PE files
  and fixed-address ELF match. Not verified for every format.
* **Offsets vs. Ghidra:** offsets are radare2's loaded addresses; if you rebased
  the program in Ghidra, they will not match.