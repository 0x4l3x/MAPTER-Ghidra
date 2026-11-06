#!/usr/bin/env bash
# ============================================================
# capa_bulk.sh - Bulk-run FLARE capa on many binaries (Linux / macOS).
#
# OPTIONAL helper: the MAPTER pipeline (mapter_pipeline.py, stage "capa") does
# the same in Python and is what the Ghidra plugin uses. Use this script to
# run capa by hand over a large set, then simplify the reports with
#   python capa_simplifier.py -d <output_dir> -o <dataset>/capa
#
# Input is one of:
#   -d <dir>   every regular file below <dir> (sha256 is computed)
#   -l <tsv>   list with one "<sha256><TAB><path>" per line (paths may contain
#              spaces and commas; lines starting with # are ignored)
#   -c <csv>   CSV with a header (columns sha256,path - see -s/-p), parsed with
#              python3's csv module so quoting, spaces and commas are safe
#
# Output: <output_dir>/<sha256>.json (raw capa report, written atomically)
#         <output_dir>/capa_bulk.log, errors.tsv, skipped.tsv
#
# Example:
#   ./capa_bulk.sh -b ~/.mapter/tools/capa/capa -d ~/samples -o ./capa_raw -j 4 -t 600
# ============================================================

set -euo pipefail

# --- Configuration (all overridable by options / environment) ---
CAPA_BINARY="${CAPA:-}"
OUTPUT_DIR="./capa_raw"
INPUT_DIR=""
INPUT_TSV=""
INPUT_CSV=""
SHA256_COL="sha256"   # CSV header name (or 1-based position with -H)
PATH_COL="path"
CSV_HAS_HEADER=true
TIMEOUT_SECS=600
MAX_PARALLEL=4
SKIP_EXISTING=true

if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'
else
    RED=""; YELLOW=""; GREEN=""; NC=""
fi

usage() {
    cat <<EOF
Usage: $(basename "$0") (-d <dir> | -l <list.tsv> | -c <list.csv>) [OPTIONS]

Input (exactly one):
  -d <dir>            Process every regular file below <dir>
  -l <tsv_file>       "<sha256><TAB><path>" per line
  -c <csv_file>       CSV with sha256 and path columns (see -s, -p, -H)

Options:
  -o <output_dir>     Output directory (default: $OUTPUT_DIR)
  -b <capa_binary>    capa executable (default: \$CAPA, then PATH, then
                      \$MAPTER_TOOLS_DIR/capa/capa or ~/.mapter/tools/capa/capa)
  -s <col>            CSV column of the sha256 (name, or 1-based position with -H)
  -p <col>            CSV column of the path
  -H                  CSV has no header row
  -t <seconds>        Timeout per binary (default: $TIMEOUT_SECS; needs timeout/gtimeout)
  -j <jobs>           Parallel jobs (default: $MAX_PARALLEL; capa is memory hungry)
  -n                  Sequential mode (same as -j 1)
  -f                  Force reprocessing (do not skip existing outputs)
  -h                  This help
EOF
}

# --- Argument parsing ---
while getopts "d:l:c:o:b:s:p:t:j:nHfh" opt; do
    case $opt in
        d) INPUT_DIR="$OPTARG" ;;
        l) INPUT_TSV="$OPTARG" ;;
        c) INPUT_CSV="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        b) CAPA_BINARY="$OPTARG" ;;
        s) SHA256_COL="$OPTARG" ;;
        p) PATH_COL="$OPTARG" ;;
        t) TIMEOUT_SECS="$OPTARG" ;;
        j) MAX_PARALLEL="$OPTARG" ;;
        n) MAX_PARALLEL=1 ;;
        H) CSV_HAS_HEADER=false ;;
        f) SKIP_EXISTING=false ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

die() { echo "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# --- Validate inputs ---
n_inputs=0
[[ -n "$INPUT_DIR" ]] && n_inputs=$((n_inputs + 1))
[[ -n "$INPUT_TSV" ]] && n_inputs=$((n_inputs + 1))
[[ -n "$INPUT_CSV" ]] && n_inputs=$((n_inputs + 1))
[[ $n_inputs -eq 1 ]] || { usage >&2; die "give exactly one of -d, -l, -c"; }
[[ -z "$INPUT_DIR" || -d "$INPUT_DIR" ]] || die "directory not found: $INPUT_DIR"
[[ -z "$INPUT_TSV" || -f "$INPUT_TSV" ]] || die "list not found: $INPUT_TSV"
[[ -z "$INPUT_CSV" || -f "$INPUT_CSV" ]] || die "CSV not found: $INPUT_CSV"

for val in "$TIMEOUT_SECS" "$MAX_PARALLEL"; do
    [[ "$val" =~ ^[0-9]+$ && "$val" -gt 0 ]] || die "invalid numeric argument: $val"
done

if [[ -z "$CAPA_BINARY" ]]; then
    if command -v capa >/dev/null 2>&1; then
        CAPA_BINARY="$(command -v capa)"
    elif [[ -x "${MAPTER_TOOLS_DIR:-$HOME/.mapter/tools}/capa/capa" ]]; then
        CAPA_BINARY="${MAPTER_TOOLS_DIR:-$HOME/.mapter/tools}/capa/capa"
    fi
fi
[[ -n "$CAPA_BINARY" && -f "$CAPA_BINARY" ]] || die "capa binary not found (use -b or set CAPA)"
[[ -x "$CAPA_BINARY" ]] || die "capa binary is not executable: $CAPA_BINARY"

# GNU timeout is "timeout" on Linux, "gtimeout" with Homebrew coreutils on macOS.
TIMEOUT_CMD=""
for c in timeout gtimeout; do
    if command -v "$c" >/dev/null 2>&1; then TIMEOUT_CMD="$(command -v "$c")"; break; fi
done

# sha256 of a file: sha256sum (Linux) or shasum (macOS)
if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "neither sha256sum nor shasum found"
fi

# --- Directories and logs (everything lives in the output dir) ---
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
LOG_FILE="$OUTPUT_DIR/capa_bulk.log"
SKIP_LOG="$OUTPUT_DIR/skipped.tsv"
ERROR_LOG="$OUTPUT_DIR/errors.tsv"
: > "$ERROR_LOG"
: > "$SKIP_LOG"

STATS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/capa_bulk.XXXXXX")"
trap 'rm -rf "$STATS_DIR"' EXIT

log() {
    local level="$1"; shift
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" | tee -a "$LOG_FILE"
}
inc_stat() { echo 1 >> "$STATS_DIR/$1"; }
get_stat() { if [[ -f "$STATS_DIR/$1" ]]; then wc -l < "$STATS_DIR/$1" | tr -d ' '; else echo 0; fi; }

# --- Build the work list: NUL-separated "sha256 \0 path \0" records ---
LIST_FILE="$STATS_DIR/list.nul"
: > "$LIST_FILE"

if [[ -n "$INPUT_DIR" ]]; then
    log "INFO" "Hashing files below $INPUT_DIR ..."
    while IFS= read -r -d '' f; do
        printf '%s\0%s\0' "$(sha256_of "$f")" "$f" >> "$LIST_FILE"
    done < <(find "$INPUT_DIR" -type f -print0)
elif [[ -n "$INPUT_TSV" ]]; then
    while IFS=$'\t' read -r sha path || [[ -n "${sha:-}" ]]; do
        sha="${sha%$'\r'}"; path="${path%$'\r'}"
        [[ -z "$sha" || "$sha" == \#* || -z "${path:-}" ]] && continue
        printf '%s\0%s\0' "$sha" "$path" >> "$LIST_FILE"
    done < "$INPUT_TSV"
else
    command -v python3 >/dev/null 2>&1 || die "-c needs python3 (or use -l with a TSV)"
    python3 - "$INPUT_CSV" "$SHA256_COL" "$PATH_COL" "$CSV_HAS_HEADER" > "$LIST_FILE" <<'PY'
import csv, sys
src, sha_col, path_col, header = sys.argv[1:5]
with open(src, newline="", encoding="utf-8-sig") as fh:
    rows = list(csv.reader(fh))
if header == "true":
    names = [h.strip().lower() for h in rows[0]]
    try:
        si, pi = names.index(sha_col.lower()), names.index(path_col.lower())
    except ValueError:
        sys.exit(f"columns {sha_col!r}/{path_col!r} not found in header {rows[0]}")
    rows = rows[1:]
else:
    si, pi = int(sha_col) - 1, int(path_col) - 1
out = sys.stdout.buffer
for r in rows:
    if len(r) > max(si, pi) and r[si].strip() and r[pi].strip():
        out.write(r[si].strip().encode() + b"\0" + r[pi].encode() + b"\0")
PY
fi

TOTAL=$(( $(tr -cd '\0' < "$LIST_FILE" | wc -c | tr -d ' ') / 2 ))

log "INFO" "============================================================"
log "INFO" "capa bulk processor started"
log "INFO" "capa:       $CAPA_BINARY"
log "INFO" "Output:     $OUTPUT_DIR"
log "INFO" "Timeout:    ${TIMEOUT_SECS}s ${TIMEOUT_CMD:+(via $TIMEOUT_CMD)}"
log "INFO" "Jobs:       $MAX_PARALLEL"
log "INFO" "Skip exist: $SKIP_EXISTING"
log "INFO" "Entries:    $TOTAL"
log "INFO" "============================================================"
[[ -n "$TIMEOUT_CMD" ]] || log "WARN" "no timeout/gtimeout found: binaries run WITHOUT a time limit (brew install coreutils)"

if [[ $TOTAL -eq 0 ]]; then
    log "WARN" "No entries to process. Exiting."
    exit 0
fi

# --- Core processing function (exported for the worker shells) ---
process_binary() {
    local sha256="$1"
    local binary_path="$2"
    local output_file="$OUTPUT_DIR/${sha256}.json"
    local tmp_output

    if [[ ! "$sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        log "ERROR" "Not a sha256: '$sha256' ($binary_path)"
        printf '%s\t%s\t%s\n' "$sha256" "$binary_path" "BAD_SHA256" >> "$ERROR_LOG"
        inc_stat errors
        return 0
    fi

    if $SKIP_EXISTING && [[ -s "$output_file" ]]; then
        log "SKIP" "Already processed: $sha256"
        printf '%s\t%s\n' "$sha256" "ALREADY_EXISTS" >> "$SKIP_LOG"
        inc_stat skipped
        return 0
    fi

    if [[ ! -f "$binary_path" ]]; then
        log "ERROR" "Binary not found: $binary_path (SHA256: $sha256)"
        printf '%s\t%s\t%s\n' "$sha256" "$binary_path" "FILE_NOT_FOUND" >> "$ERROR_LOG"
        inc_stat errors
        return 0
    fi

    log "INFO" "Processing: $sha256 -> $binary_path"

    # Temp file in the output dir (same filesystem => atomic mv). No suffix after
    # the X's: BSD/macOS mktemp does not substitute them in that case.
    tmp_output="$(mktemp "$OUTPUT_DIR/.${sha256}.XXXXXX")"

    local exit_code=0
    if [[ -n "$TIMEOUT_CMD" ]]; then
        "$TIMEOUT_CMD" "$TIMEOUT_SECS" "$CAPA_BINARY" "$binary_path" --json > "$tmp_output" 2>>"$LOG_FILE" || exit_code=$?
    else
        "$CAPA_BINARY" "$binary_path" --json > "$tmp_output" 2>>"$LOG_FILE" || exit_code=$?
    fi

    if [[ $exit_code -eq 124 ]]; then
        log "ERROR" "TIMEOUT after ${TIMEOUT_SECS}s: $sha256 ($binary_path)"
        printf '%s\t%s\t%s\n' "$sha256" "$binary_path" "TIMEOUT" >> "$ERROR_LOG"
        rm -f "$tmp_output"
        inc_stat errors
        return 0
    fi

    if [[ $exit_code -ne 0 ]]; then
        # 14 file limitation, 16/17/18 unsupported type/arch/OS: expected for some files
        log "ERROR" "capa exited with code $exit_code for: $sha256 ($binary_path)"
        printf '%s\t%s\t%s\n' "$sha256" "$binary_path" "CAPA_EXIT_$exit_code" >> "$ERROR_LOG"
        rm -f "$tmp_output"
        inc_stat errors
        return 0
    fi

    if [[ ! -s "$tmp_output" ]]; then
        log "ERROR" "capa produced no output for: $sha256 ($binary_path)"
        printf '%s\t%s\t%s\n' "$sha256" "$binary_path" "EMPTY_OUTPUT" >> "$ERROR_LOG"
        rm -f "$tmp_output"
        inc_stat errors
        return 0
    fi

    chmod 644 "$tmp_output"   # mktemp creates 0600
    mv "$tmp_output" "$output_file"
    log "OK" "Done: $sha256 -> $output_file"
    inc_stat success
    return 0
}

export -f process_binary inc_stat log
export CAPA_BINARY OUTPUT_DIR TIMEOUT_SECS TIMEOUT_CMD SKIP_EXISTING STATS_DIR LOG_FILE ERROR_LOG SKIP_LOG

# --- Execution ---
START_TIME=$(date +%s)

# xargs -P (BSD and GNU) instead of GNU parallel; NUL-separated pairs keep
# spaces, commas and newlines in paths intact.
xargs -0 -n 2 -P "$MAX_PARALLEL" bash -c 'process_binary "$1" "$2"' _ < "$LIST_FILE" || true

# --- Final report ---
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02dh:%02dm:%02ds' $((ELAPSED/3600)) $((ELAPSED%3600/60)) $((ELAPSED%60)))

SUCCESS=$(get_stat success)
ERRORS=$(get_stat errors)
SKIPPED=$(get_stat skipped)

log "INFO" "============================================================"
log "INFO" "Processing complete in $ELAPSED_FMT"
log "INFO" "  Total:   $TOTAL"
echo "${GREEN}  Success: $SUCCESS${NC}";  echo "  Success: $SUCCESS" >> "$LOG_FILE"
echo "${YELLOW}  Skipped: $SKIPPED${NC}"; echo "  Skipped: $SKIPPED" >> "$LOG_FILE"
echo "${RED}  Errors:  $ERRORS${NC}";    echo "  Errors:  $ERRORS" >> "$LOG_FILE"
log "INFO" "  Log:     $LOG_FILE"
log "INFO" "  Errors:  $ERROR_LOG"
log "INFO" "============================================================"
