# MAPTER ↔ Ghidra integration

Reference for the link between the MAPTER Dash app and Ghidra. For a short
install guide see [README.md](README.md).

## Overview

```
 Dash app (browser, :15510)                 Ghidra CodeBrowser
 ─────────────────────────                  ──────────────────────────────
 click point ── POST /navigate ───────────▶ MapterBridge plugin (:9999)
                                            switch/open program, go to
                                            function, highlight it
 "Follow Ghidra" ◀── GET /current (1 s) ─── cursor moves (location events)
 ring point / switch cluster
                                            Tools → MAPTER → Open MAPTER
 python app.py ◀───────── starts ────────── (bundled app + APT_19 data)
```

- **Join key:** `(binary_name, offset)`. `offset` is the loaded virtual address
  (e.g. `0x401000`), used as-is in Ghidra's default address space. The Ghidra
  program name is the full hash; `binary_name` may be a truncated prefix.
- **Name matching** (both directions): exact → prefix → substring,
  case-insensitive; ambiguous matches are rejected, never guessed.
- **One project:** all binaries live in one Ghidra project; `/navigate`
  switches to (or opens) the right program on every request.

## Components

| Piece | Where | Role |
| --- | --- | --- |
| MapterBridge extension | `MapterBridge/` (Java) | HTTP server in Ghidra, cursor tracking, app launcher |
| `ghidra_integration.py` | Dash app | `GhidraClient` (`/status`, `/navigate`, `/current`), name/offset matching helpers |
| `app.py` | Dash app | click → navigate callback; Follow Ghidra poll + highlight callbacks |
| `viz_components.py` | Dash app | scatter with `customdata = [offset, name, binary_name]` and the ring overlay trace |
| `requirements-app.txt` | Dash app | packages the app needs at runtime (used by the environment setup) |
| `MAPTER_backend/` | Generation pipeline | `mapter_pipeline.py` and its stages: binaries → MAPTER data folder ([README](MAPTER_backend/README.md)) |

The extension zip bundles the app's Python files, `requirements-app.txt`,
`datasets/APT_19` and `datasets/capa/APT_19` under
`MapterBridge/data/mapter_app/`, and the generation pipeline (`MAPTER_backend`,
including the ~220 MB SAFE model, so it runs offline) under
`MapterBridge/data/mapter_backend/`, copied from this repo at build time (the
zip is about 200 MB).

## Setup

1. **Install** the zip matching your Ghidra version (File → Install
   Extensions), restart, enable **MapterBridgePlugin** in the CodeBrowser. Zips
   are tied to the exact Ghidra version; build one per install (see
   "Build from source" in [README.md](README.md)).
2. **Import** every binary of the dataset into one project, named by its hash.
3. **Python:** **Tools → MAPTER → Python Environment…** (see below) to use an
   existing environment or create one.
4. **Tools → MAPTER → Open MAPTER.**

## Using it

**Dash → Ghidra.** Click a point in Cluster Detail. Ghidra makes the
function's program current (opening it from the project if needed), goes to
the function and highlights its body. The highlight is transient: it does
not modify the program and is cleared on the next navigation. A toast in
the app reports the result.

**Ghidra → Dash ("Follow Ghidra", on by default).** The app polls
`GET /current` every second and acts only when the function changes:

| Situation | What the app does |
| --- | --- |
| Function shown in Cluster Detail | Red ring on its point |
| Its binary is in another cluster | Selects that cluster; Cluster Detail redraws with the ring (the tab is not changed) |
| In the shown cluster but filtered out | Status "hidden by the current filters"; filters are left alone |
| You opened another cluster yourself | Stays; status "in C*n*, not shown" |
| Cursor outside a function / program not in dataset / Ghidra closed | Ring cleared, status explains |

Changing cluster clears the Binary and Function filter selections (they name
members of the previous cluster); CAPA rule/library filters are kept. Zoom is
kept across filter changes and ring updates.

**Menu (CodeBrowser → Tools → MAPTER).**

| Item | Action |
| --- | --- |
| MAPTER Data Folder… | Chooses this Ghidra project's MAPTER data folder (saved in the project), or the bundled sample |
| Run MAPTER Pipeline… | Generates MAPTER data from this project's programs or from a folder of binaries ([below](#generating-mapter-data-pipeline)) |
| Open MAPTER | Starts the app with the project's data if nothing listens on the Dash port (restarts the app it started if the folder changed), then opens the browser |
| Stop MAPTER App | Stops the app started from this tool, or asks a MAPTER app found on the Dash port (e.g. started by hand) to exit via `POST /_mapter/shutdown` (local only). The app Ghidra started also stops when the tool closes |
| Navigation Server | Toggles the HTTP server (auto-starts with the tool) |
| Python Environment… | Find, choose, create or complete the Python environment of the **app** (below) |

## Data and controls

Each Ghidra project points to one MAPTER data folder (**Tools → MAPTER → MAPTER
Data Folder…**, format in [datasets/README.md](datasets/README.md)); the app
then shows that dataset read-only instead of a dataset dropdown. The left panel
has two steps:

- **1 · Compare binaries** (press **Recompute Similarity** after changing):
  *Neighbour radius δ* — functions of two binaries closer than δ count as
  shared; *Min. shared functions (%)* — two binaries are linked only if at
  least this share of each one's functions is shared.
- **2 · Group into clusters** (live): *Number of clusters* cuts the dendrogram
  into that many groups; *Advanced: cut height* shows/sets the same cut as a
  height on the dendrogram's distance axis. Identical binaries (distance 0)
  can make some counts unreachable; the readout shows the real number.

## Choosing δ (Suggest δ)

δ is the **Function Similarity Threshold**: the radius within which a function
of one binary counts as close to a function of another. **Suggest δ** (left
panel) runs `recommend_delta.py` on the selected dataset (about 2 s, then
cached): it samples pairs of (almost always unrelated) binaries, takes each
function's distance to the nearest function of the other binary, and
recommends the range between the first non-zero percentile and the 50th of
those distances. Candidate radii are shown as buttons (hover for the 95%
bootstrap interval); clicking one fills in the threshold, and the line below
says where the current δ falls (percentile, below/inside/above the range).
Choose with known relations or by inspecting the dendrogram (too large a δ
merges binaries into a few groups), then press **Recompute Clusters**. The
same script works from the command line:
`python recommend_delta.py datasets/APT_19/reduced.pkl --delta 5`.

## Python environment

The app needs the packages in `requirements-app.txt` (with those minimum
versions; e.g. numpy ≥ 2 to read the pickles). **Tools → MAPTER → Python
Environment…** manages which Python runs it:

- **Automatic exploration.** On opening, the dialog checks every interpreter
  it can find: the configured one, `mapter-venv` in the settings folder of
  every Ghidra version (so an upgrade can reuse it), `.venv`/`venv` next to
  `app.py`, the active `VIRTUAL_ENV`/`CONDA_PREFIX`, `~/.virtualenvs`,
  `~/venvs`, `~/.venvs`, `~/envs`, `~/.pyenv/versions`, conda installs
  (`~/miniconda3`, `~/anaconda3`, `~/miniforge3`, `~/mambaforge`, …, and their
  `envs/`) and the system Pythons. Each row shows ✔ (ready) or what is
  missing; ready ones are listed first. **Rescan** repeats it.
- **Use Selected** stores the choice in the **Python Environment** option (the
  environment folder, or the interpreter for a system Python). If packages are
  missing it offers to install them.
- **Browse…** accepts a venv/conda folder or a `python` executable.
- **Create New…** asks for a folder (default `mapter-venv` in Ghidra's settings
  folder, e.g. `~/Library/ghidra/ghidra_11.3.2_PUBLIC/mapter-venv`), creates a
  venv with the system `python3` and installs the requirements. Log:
  `mapter-setup.log`.
- **Install Packages** installs/upgrades the requirements in the selected
  environment. It is disabled for system Pythons, which pip should not modify.

**Open MAPTER** checks the Python it is about to use and offers this dialog if
it is not ready.

## Generating MAPTER data (pipeline)

If you have binaries but no MAPTER data, **Tools → MAPTER → Run MAPTER
Pipeline…** builds a data folder for you: radare2 + SAFE function embeddings,
CAPA capabilities, AVClass family labels (optional) and a 2D map (t-SNE by
default), merged into one `reduced.pkl` (format:
[datasets/README.md](datasets/README.md)). The work is done by the command-line
program `MAPTER_backend/mapter_pipeline.py` (see
[MAPTER_backend/README.md](MAPTER_backend/README.md)); Ghidra only prepares the
input and launches it.

**Dialog.**

- **Input:** *Programs of this Ghidra project* (their **original** imported
  files are exported; each is checked against the program's `Executable SHA256`,
  and programs whose original bytes are unavailable are listed and skipped) or
  *A folder of binaries*.
- **Work folder:** (default `<Ghidra user settings>/mapter-runs/<project>`) where everything is written (`binaries/`, `embeddings/`,
  `status.json`, `pipeline.log`, `data_folder/`, ...). Reuse the same folder to
  resume.
- **Dataset name** and **Dimensionality reduction:** t-SNE sweep (default),
  UMAP (needs `umap-learn`), PCA only, or Fixed (legacy: PCA 40 + t-SNE
  perplexity 50).
- **AVClass labels (optional):** a folder of VirusTotal reports named
  `<sha256>.json`, and/or *Fetch missing reports from VirusTotal* with an API
  key (used for this run only, not stored). Only hashes are looked up; files are
  never uploaded. A free key allows 4 requests/minute and 500/day, so large
  projects take several days of resumed runs.
- **Prerequisites panel:** shows what is missing (pipeline Python packages,
  radare2 >= 6, capa, the SAFE model) with the buttons **Python Environment…**
  (choose or create the *pipeline* environment; separate from the app's, it
  holds torch), **Install capa** (downloads the standalone release into
  `~/.mapter/tools`, shared by every Ghidra version and the CLI, checksum-verified) and **Install
  radare2**, plus **Check again**. capa and the VirusTotal reports are optional; radare2,
  the Python packages and the model are required.
- **Run / Cancel Run / Open Log:** the pipeline runs as a **detached process**
  and keeps going if you close the dialog, the CodeBrowser or Ghidra; reopen
  the dialog to see its progress (stage, binary *n* of *N*) or to cancel.
  *Cancel Run* stops the run within about 20 s (an interrupted binary is redone on resume) (a second click kills
  it); finished per-binary results are kept, so *Run* again resumes.

**When it finishes** the project's **MAPTER Data Folder** is set to the output
(`<work>/data_folder`); use **Open MAPTER** to see the map. Programs keep their
Ghidra names: `binaries.json` in the data folder maps each `binary_name` (first
6 hex characters of the sha256) to the program, and the navigation matcher
checks the program's SHA-256 before its name, so projects whose programs are
not named by hash still work.

**Requirements.** The extension bundles all of `MAPTER_backend`, including the
SAFE model (`SAFEtorch.pt` ~220 MB, `word2id.json`); to run your working copy
set **MAPTER Backend Folder**, and **SAFE Model Folder** only to use another
model.
The same pipeline runs without Ghidra: `python mapter_pipeline.py --work W
--binaries DIR` (see the backend README).

## Options (Edit → Tool Options → MAPTER Bridge)

| Option | Default | Notes |
| --- | --- | --- |
| Server Host | `127.0.0.1` | Loopback only; other values are rejected |
| Server Port | `9999` | Passed to the launched app (`MAPTER_GHIDRA_PORT`) |
| Start Server Automatically | on | |
| Dash Port | `15510` | Passed to the launched app (`MAPTER_PORT`) |
| Python Environment | empty | Environment folder or interpreter; set via the dialog. Empty → `mapter-venv`, then `.venv` next to `app.py`, then `python3` |
| MAPTER App Folder | empty | Empty → bundled copy; set it to a repo checkout to run your working copy |
| Pipeline Python Environment | empty | Environment (folder or interpreter) that runs the pipeline: torch, r2pipe, scikit-learn... Set via **Run MAPTER Pipeline…**. Empty → `mapter-pipeline-venv` in the settings folder, then `.venv` next to `mapter_pipeline.py`, then `python3` |
| MAPTER Backend Folder | empty | Folder with `mapter_pipeline.py`. Empty → bundled copy (`data/mapter_backend`); set it to a `MAPTER_backend` checkout |
| SAFE Model Folder | empty | Folder with `SAFEtorch.pt` and `word2id.json`. Empty → `model/` inside the backend folder (bundled with the extension) |
| radare2 Path | empty | radare2 executable (>= 6). Empty → found on `PATH` |
| capa Path | empty | capa executable. Empty → `PATH` or the copy installed by **Install capa** |

When you run `python app.py` by hand, the same environment variables (and
`MAPTER_DEBUG=1` to turn on Flask's debug mode, which is off by default)
override `config.py`.

## HTTP API (127.0.0.1:9999)

All replies are JSON with CORS headers; request bodies are limited to 4 KB.

**`GET /status`**
```json
{"status": "running", "message": "Ghidra navigation server is active",
 "ghidra_available": true, "current_program": "1b4491…", "program_count": 1,
 "project_program_count": 32}
```

**`POST /navigate`** — body `{"address": "0x40ac66", "binary_name": "1b4491",
"name": "fcn.0040ac66"}` (`name` optional fallback; `address` or `name`
required, `binary_name` required).
- 200 `{"success": true, "message": "Navigated", "function_name", "address", "binary"}`
- 400 bad JSON / missing or non-string fields; 404 `{"success": false, "error"}`
  when the program or function is not found or the name is ambiguous; 500 on
  an internal error.

**`GET /current`**
```json
{"success": true, "program": "1b4491…", "function_name": "FUN_00414600",
 "entry_address": "0x414600", "address": "0x41462a"}
```
Fields are `null` when unknown (no program, cursor outside a function, or a
non-default address space such as an overlay).

**`POST /shutdown`** stops the server (not Ghidra).

```bash
curl http://127.0.0.1:9999/status
curl http://127.0.0.1:9999/current
curl -X POST http://127.0.0.1:9999/navigate -H 'Content-Type: application/json' \
     -d '{"address": "0x14600", "binary_name": "1b4491"}'
```

## Troubleshooting

- **"Ghidra server not available" / status "Ghidra not reachable".** Check
  that the CodeBrowser is open, the plugin is enabled and **Navigation Server**
  is ticked; `curl …/status`. Only one CodeBrowser window can own the port; the
  others log a warning.
- **"No program in the project matches binary_name".** The binary is not
  imported, or its program name does not contain the hash. "Ambiguous" means
  several programs match; rename them.
- **"Function not found by address or name".** The offset is not a function
  entry in that program (check the image base: offsets are used without
  rebasing).
- **"Could not start the MAPTER app".** The dialog shows the end of the app
  log (`mapter-app.log` in Ghidra's user settings folder). For Python problems
  use **Tools → MAPTER → Python Environment…**; installs log to
  `mapter-setup.log`.
- **Run MAPTER Pipeline: a prerequisite is red.** Pipeline Python packages →
  **Python Environment…** (create/complete the pipeline env). radare2 → needs
  version 6 or newer (`radare2 -v`; Linux distro packages are often older, see
  [MAPTER_backend/README.md](MAPTER_backend/README.md)). SAFE model → it is
  bundled; if it is reported missing, clear **SAFE Model Folder** (or point it at
  a folder with `SAFEtorch.pt` and `word2id.json`). capa is optional: without it the map has no CAPA
  columns.
- **The pipeline failed or was interrupted.** **Open Log** shows the end of
  `pipeline.log`; `status.json` in the work folder lists per-binary failures.
  Press **Run** again with the same work folder to resume.
- **Programs were skipped when exporting.** Their original bytes are not in the
  Ghidra database (or do not match the program's SHA-256), or the program needs
  a Ghidra upgrade: open it once in Ghidra. Use *A folder of binaries* for
  those.
- **Port 15510 or 9999 in use.** Something else listens there (e.g. a
  hand-started app; Open MAPTER then just opens the browser). Change the ports
  in the options.
- **Clicking in the Decompiler doesn't move the ring.** Follow Ghidra relies on
  CodeBrowser location events; report it if the Decompiler doesn't fire them in
  your version.

## Security

Everything binds to localhost. The navigation server refuses non-loopback
hosts, limits request size and needs no authentication because nothing
outside the machine can reach it. For remote use, tunnel instead of exposing
it (`ssh -L 9999:localhost:9999 …`).
