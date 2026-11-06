# MAPTER data folders

A **MAPTER data folder** holds the precomputed map of one set of binaries
(SAFE function embeddings reduced to 2D, plus optional labels and CAPA
results). This is the contract between the app and whatever produces the data:
the research notebooks and the MAPTER generation pipeline
(`MAPTER_backend/mapter_pipeline.py`: radare2 + SAFE embeddings, CAPA, AVClass
labels and dimensionality reduction), which writes exactly this layout (see
"Pipeline-generated folders" below).

The bundled APT 19 sample (`datasets/APT_19/`, `datasets/capa/APT_19/`)
contains derived data only: function coordinates, truncated SHA-256 hashes,
CAPA results and AVClass labels. No malware binaries are distributed.

## Where the app looks

- **From Ghidra (MapterBridge):** each Ghidra project remembers its folder
  (**Tools → MAPTER → MAPTER Data Folder…**); Open MAPTER passes it to the app
  as `MAPTER_DATA`, and the app shows only that dataset. Without a folder the
  bundled sample (APT 19) is shown.
- **Run by hand (`python app.py`):** every subfolder of this `datasets/`
  directory that has a `reduced.pkl` appears in the *Dataset* dropdown. Set
  `MAPTER_DATA=/path/to/folder` to show a single folder instead.

## Layout

```
<folder>/
  reduced.pkl      # 2D map + function metadata (required)
  avclass.pkl      # per-binary family labels (optional)
  capa/            # CAPA JSON results, one per binary (optional)
  binaries.json    # binary_name -> sha256 / Ghidra program (optional)
  dataset.json     # metadata: display name, default thresholds (optional)
```

Only `reduced.pkl` is required; the folder name is the dataset id unless
`dataset.json` says otherwise. Older layouts that keep CAPA results in a shared
`datasets/capa/<id>/` folder are still read.

## `dataset.json`

```json
{
  "id": "APT_21",
  "name": "APT 21",
  "description": "APT21 malware binaries — SAFE embeddings reduced to 2D.",
  "reduced": "reduced.pkl",
  "avclass": "avclass.pkl",
  "avclass_apt_group": "APT_21"
}
```

| field               | required | meaning                                                                 |
|---------------------|----------|-------------------------------------------------------------------------|
| `id`                | no       | Dataset id. Defaults to the folder name.                                |
| `name`              | no       | Display name. Defaults to `id`.                                         |
| `description`       | no       | Short help text.                                                        |
| `reduced`           | no       | Filename of the reduced-embeddings pickle. Defaults to `reduced.pkl`.   |
| `avclass`           | no       | Filename of the AVClass-label pickle. Omit if you have no labels.       |
| `avclass_apt_group` | no       | If the avclass table has an `apt_group` column, keep only this group.   |
| `default_function_threshold` | no | Initial neighbour radius δ (UI: "Neighbour radius δ").               |
| `default_binary_threshold`   | no | Initial min. shared functions, as a fraction (0.2 = 20 % in the UI). |
| `default_distance_threshold` | no | Initial dendrogram cut height (UI: "Advanced: cut height"; sets the number of clusters). |
| `avclass_threshold`          | no | Distance below which clusters get an avclass tag label (higher = tags on broader clusters). Falls back to `config.LIMIT_RELEVANT_CLUSTERS`. |

`dataset.json` itself is optional, and so is every key in it. The four threshold keys are optional; each falls back to the matching value in
`config.py` when absent. They let each dataset carry sensible starting points
(datasets differ in scale), which the user can still adjust live in the UI.

## `reduced.pkl` (required)

A pandas DataFrame with **at least** these columns:

| column        | type    | meaning                                                            |
|---------------|---------|--------------------------------------------------------------------|
| `binary_name` | str     | Identifies the binary (e.g. a truncated hash). Groups functions.   |
| `offset`      | str     | Function entry address, hex, e.g. `0x401000`. The **loaded VA** —  |
|               |         | used by the Ghidra navigation link exactly as stored.              |
| `name`        | str     | Function name / label.                                             |
| `size`        | numeric | Function size (used for point sizing).                             |
| `x`, `y`      | float   | 2D embedding coordinates to plot.                                  |

Extra columns are preserved and available to hover/filters.

### Optional enrichment columns

The Cluster Detail View shows extra filters **only when** the dataset provides
the matching column — otherwise the filter is hidden automatically. Include any
of these to enable the corresponding filter:

| column                  | enables                                             |
|-------------------------|-----------------------------------------------------|
| `rule_name`             | CAPA-rule filters + the "CAPA Rules" dropdown (also filled from `capa/`) |
| `library_name`          | library-function filters + the "Library" dropdown (also filled from `capa/`) |
| `avclass_label`         | per-binary AVClass tags (used when there is no `avclass.pkl`) |
| `has_strings`           | the "String Content" filter                          |
| `has_external_function` | the "External Calls" filter                          |

The CAPA columns are `rule_name`, `tactic`, `technique`, `subtechnique`,
`attack_id`, `objective`, `behavior`, `method`, `mbc_id` and `library_name`
(multiple values for one function are joined with `; `). If `reduced.pkl`
already has `rule_name` or `library_name`, the app uses these columns as they
are and does **not** merge the `capa/` folder again; otherwise CAPA results
found in `capa/` are merged on `(binary_name, offset)` as before.

A minimal dataset with just the six required columns works fine; it simply shows
the always-available filters (binary name, function name, size).

## `avclass.pkl` (optional)

A pandas DataFrame with a `binary_name` column and a `label` column (extra
columns ignored). Rows are matched to the binaries present in `reduced.pkl`. If
you set `avclass_apt_group` and the table has an `apt_group` column, it is
filtered to that group first. A single multi-group table can therefore be reused
across datasets by pointing each manifest at it with a different
`avclass_apt_group`.

If there is no `avclass.pkl` but `reduced.pkl` has an `avclass_label` column,
the tags are taken from it (first non-null label per `binary_name`).
`avclass.pkl`, when present, takes precedence (backward compatibility).

## Enriched single pickle (pipeline output)

`mapter_pipeline.py` writes ONE enriched `reduced.pkl`: the required columns
plus

- `sha256` (str): SHA-256 of the binary the function belongs to;
- the ten CAPA columns listed above (empty/NaN when CAPA found nothing for
  that function or was not run);
- `avclass_label` (str): AVClass label of the binary, repeated on each of its
  rows (`None` when the label is unknown, `-` when no AV labels were available).

`x`, `y` are float32 and `offset` is the lowercase, unpadded hex loaded VA.
`avclass.pkl` (`binary_name`, `label`, ...) and `capa/<sha256>.json`
(simplified CAPA results) are also written for provenance; the app reads the
columns in `reduced.pkl` directly.

## `binaries.json`

Written by the pipeline; maps each `binary_name` to the binary it stands for
(the app does not need it, tools and the Ghidra extension can use it):

```json
{
  "1b4491": {
    "sha256": "1b4491...(64 hex chars)",
    "program_name": "sample.exe",
    "domain_path": "/sample.exe",
    "path": "binaries/1b4491....."
  }
}
```

`binary_name` is the first 6 hex characters of the SHA-256 (longer only to
resolve a collision). The Ghidra link matches the open program to a
`binary_name` by SHA-256 prefix first, then by program name.

## Pipeline-generated `dataset.json`

Besides the keys above, `mapter_pipeline.py` records provenance:

| field                | meaning                                              |
|----------------------|------------------------------------------------------|
| `generated_by`       | always `"mapter_pipeline"`                           |
| `created`            | creation timestamp (ISO 8601)                        |
| `method`             | reduction method: `tsne`, `umap`, `pca` or `fixed`   |
| `n_binaries`         | number of binaries in the map                        |
| `n_functions`        | number of functions (rows of `reduced.pkl`)          |
| `default_function_threshold` | suggested neighbour radius δ (from `recommend_delta`, else 5.0) |
| `default_binary_threshold`   | 0.2                                          |
| `default_distance_threshold` | 0.75                                         |
| `avclass_threshold`  | 0.9                                                  |

## Ghidra navigation

The `offset` column must be the **loaded virtual address** Ghidra uses (e.g.
`0x401000` for a 32-bit PE based at `0x400000`). No rebasing is applied. See
`GHIDRA_INTEGRATION_README.md` for the navigation server.
