"""
Configuration of the MAPTER web app.
"""

import os

# ============================================================================
# Data Configuration
# ============================================================================

# Default dataset shown on load. Must match a folder id under datasets/
# (see datasets/README.md). If None or not found, the first discovered
# dataset is used. Datasets are selectable at runtime via the app's dropdown.
DEFAULT_DATASET_ID = "APT_19"

# ============================================================================
# Clustering Configuration (datasets may override them in dataset.json)
# ============================================================================

# Default neighbour radius δ (function similarity threshold)
DEFAULT_FUNCTION_THRESHOLD = 1.0

# Default min. shared functions, as a fraction (binary similarity threshold)
DEFAULT_BINARY_THRESHOLD = 0.2

# Default dendrogram cut height (sets the number of clusters)
DEFAULT_DISTANCE_THRESHOLD = 0.75

# ============================================================================
# Visualization Configuration
# ============================================================================

# Dendrogram height in pixels (y-axis / distance direction).
DENDROGRAM_HEIGHT = 480

# Dendrogram width scales with the number of binaries so small datasets aren't
# stretched and large ones stay readable (scrolls horizontally past the panel).
DENDROGRAM_PX_PER_BINARY = 16
DENDROGRAM_MIN_WIDTH = 600
DENDROGRAM_MAX_WIDTH = 1800

# avclass tag annotation distance threshold: clusters merging BELOW this height
# get a dominant-tag label. Higher = tags shown for broader clusters. Only
# applied when the dataset has avclass tags. Datasets may override it via the
# manifest key "avclass_threshold".
LIMIT_RELEVANT_CLUSTERS = 0.9

# ============================================================================
# Application Configuration
# ============================================================================

# Server host
SERVER_HOST = 'localhost'

# Server port. MAPTER_PORT overrides it (set by Ghidra's MapterBridge when it
# launches the app, from its "Dash Port" option).
SERVER_PORT = int(os.environ.get("MAPTER_PORT", 15510))

# Debug mode (Flask debugger + reloader). Off by default; MAPTER_DEBUG=1 turns
# it on for development. The MapterBridge launcher always sets MAPTER_DEBUG=0,
# so stopping the app leaves no reloader child.
DEBUG_MODE = os.environ.get("MAPTER_DEBUG", "0") == "1"

# Logging configuration
LOGGING_LEVEL = 'INFO'  # Options: DEBUG, INFO, WARNING, ERROR

# ============================================================================
# Ghidra Integration
# ============================================================================

# Navigation server exposed by the MapterBridge Ghidra extension (see
# GHIDRA_INTEGRATION_README.md). The Dash app POSTs click-to-navigate requests to it.
GHIDRA_HOST = "127.0.0.1"
GHIDRA_PORT = int(os.environ.get("MAPTER_GHIDRA_PORT", 9999))  # set by MapterBridge
GHIDRA_TIMEOUT = 5.0

# Reverse link (Ghidra -> plot): the app polls GET /current and highlights the
# function under Ghidra's cursor in Cluster Detail ("Follow Ghidra" switch).
GHIDRA_POLL_INTERVAL_MS = 1000   # poll period
GHIDRA_POLL_TIMEOUT = 0.5        # seconds; kept short so a stalled Ghidra never blocks
GHIDRA_FOLLOW_DEFAULT = True     # initial state of the "Follow Ghidra" switch

# ============================================================================
# UI Configuration
# ============================================================================

# Bootstrap theme
# Options: BOOTSTRAP, FLATLY, DARKLY, CYBORG, COSMO, LITERA, etc.
BOOTSTRAP_THEME = "BOOTSTRAP"

# Application title
APP_TITLE = "MAPTER"

# Application subtitle
APP_SUBTITLE = "A Framework for Mapping APTs Through Embedding Representations"
