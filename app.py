"""
Malware Binary Clustering Interactive Dashboard
================================================
A Dash application for exploring hierarchical clustering of malware binaries
with interactive dendrogram visualization and cluster drill-down capabilities.
"""

import functools
import hashlib
import logging
import os
import threading
from collections import Counter

import flask

import dash
from dash import dcc, html, Input, Output, State, ALL, Patch, callback_context, no_update
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate
import plotly.graph_objects as go
import numpy as np
from scipy.cluster.hierarchy import fcluster, linkage
from scipy.spatial.distance import squareform

# Import custom modules
from viz_components import (DendrogramVisualizer, BinaryPlotVisualizer,
                            GHIDRA_OVERLAY_NAME, make_ghidra_overlay_trace)
from ghidra_integration import GhidraClient, match_binary_name, parse_hex_offset
import dataset_registry
import recommend_delta
import config

# Configure logging once for the whole app (backend modules use
# logging.getLogger(__name__), so this drives their output too).
logging.basicConfig(
    level=getattr(logging, str(getattr(config, "LOGGING_LEVEL", "INFO")).upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize Dash app with Bootstrap theme
theme = getattr(dbc.themes, config.BOOTSTRAP_THEME, dbc.themes.BOOTSTRAP)
app = dash.Dash(
    __name__, 
    external_stylesheets=[theme, dbc.icons.FONT_AWESOME],
    suppress_callback_exceptions=True
)
app.title = config.APP_TITLE

# Discover available datasets (public data-source format; see dataset_registry).
# Callbacks are stateless: they carry the selected dataset id and re-fetch a
# warmed processor via dataset_registry.get_processor(id). No shared mutable
# processor global — that would race across concurrent browser sessions.
DATASETS = dataset_registry.list_datasets()
_config_default = getattr(config, "DEFAULT_DATASET_ID", None)
if _config_default and any(d["id"] == _config_default for d in DATASETS):
    DEFAULT_DATASET_ID = _config_default
elif DATASETS:
    DEFAULT_DATASET_ID = DATASETS[0]["id"]
else:
    DEFAULT_DATASET_ID = None
    logger.warning("No datasets discovered under the datasets/ directory.")

dendrogram_viz = DendrogramVisualizer()
binary_viz = BinaryPlotVisualizer()

# Initialize Ghidra client for navigation
ghidra_client = GhidraClient(
    host=config.GHIDRA_HOST,
    port=config.GHIDRA_PORT,
    timeout=config.GHIDRA_TIMEOUT,
)

# ============================================================================
# Layout Components
# ============================================================================

def create_header():
    """Create application header"""
    return dbc.Container([
        dbc.Row([
            dbc.Col([
                html.H1([
                    html.I(className="fas fa-project-diagram me-3"),
                    "MAPTER"
                ], className="text-primary mb-2"),
                html.P(
                    config.APP_SUBTITLE,
                    className="lead text-muted"
                )
            ])
        ], className="mb-4")
    ], fluid=True, className="bg-light py-4 mb-4")


def _help(text):
    return html.P(text, className="small text-muted mb-1")


def _data_source_block():
    """Dataset picker when the app is run by hand; read-only when MapterBridge
    chose the data for the Ghidra project (the dropdown stays, hidden, as the
    single source of the dataset id for the callbacks)."""
    source = dataset_registry.data_source()
    dropdown = dcc.Dropdown(
        id='dataset-dropdown',
        options=[{'label': d['name'], 'value': d['id'], 'title': d['folder']} for d in DATASETS],
        value=DEFAULT_DATASET_ID,
        clearable=False,
    )
    if not source['managed']:
        return html.Div([html.Label("Dataset", className="fw-bold"), dropdown],
                        className="mb-3")
    name = next((d['name'] for d in DATASETS if d['id'] == DEFAULT_DATASET_ID), "no data")
    if source['sample']:
        note = html.Small("Sample data bundled with MapterBridge. Choose this project's data "
                          "in Ghidra: Tools → MAPTER → MAPTER Data Folder…",
                          className="text-warning d-block")
    else:
        note = html.Small(source['folder'], title=source['folder'],
                          className="text-muted d-block text-truncate")
    return html.Div([
        html.Label("Dataset", className="fw-bold d-block"),
        html.Span(name, className="fs-5"),
        note,
        html.Div(dropdown, style={'display': 'none'}),
    ], className="mb-3")


def create_control_panel():
    """Control panel: data, (1) how binaries are compared, (2) how the
    dendrogram is cut into clusters, cluster selection and Follow Ghidra."""
    return dbc.Card([
        dbc.CardHeader([
            html.H4([
                html.I(className="fas fa-sliders-h me-2"),
                "Clustering Controls"
            ])
        ]),
        dbc.CardBody([
            _data_source_block(),

            # 1. Binary-to-binary similarity (needs a recompute)
            html.H6("1 · Compare binaries", className="text-primary mt-2"),
            html.Label("Neighbour radius δ", className="fw-bold"),
            _help("Functions of two binaries closer than δ on the map count as shared."),
            dbc.Row([
                dbc.Col([
                    dcc.Input(
                        id='function-threshold-input',
                        type='number',
                        value=config.DEFAULT_FUNCTION_THRESHOLD,
                        min=0,
                        step="any",
                        className="form-control"
                    ),
                ], width=6),
                dbc.Col([
                    dbc.Button(
                        [html.I(className="fas fa-magic me-2"), "Suggest δ"],
                        id='suggest-delta-button',
                        color="secondary",
                        outline=True,
                        className="w-100",
                        title="Recommend a radius from the distances between unrelated binaries",
                    ),
                ], width=6)
            ], className="mb-2"),
            dcc.Loading(html.Div(id='delta-suggestion', className="mb-2"), type="dot"),
            html.Label("Min. shared functions (%)", className="fw-bold"),
            _help("Link two binaries only if at least this share of each one's "
                  "functions is shared."),
            dcc.Input(
                id='binary-threshold-input',
                type='number',
                value=round(100 * config.DEFAULT_BINARY_THRESHOLD, 4),
                min=0,
                max=100,
                step="any",
                className="form-control mb-2"
            ),
            dbc.Button(
                [html.I(className="fas fa-sync-alt me-2"), "Recompute Similarity"],
                id='recompute-button',
                color="primary",
                className="w-100 mb-3"
            ),

            # 2. Cut of the dendrogram (live)
            html.Hr(className="my-2"),
            html.H6("2 · Group into clusters", className="text-primary"),
            html.Label(["Number of clusters ",
                        html.Span(id='n-clusters-readout', className="small text-muted fw-normal")],
                       className="fw-bold"),
            _help("Cuts the dendrogram (red line) into this many groups."),
            dcc.Slider(
                id='n-clusters-slider',
                min=1, max=2, step=1, value=1,
                marks=None,
                tooltip={"placement": "bottom", "always_visible": True},
            ),
            html.Details([
                html.Summary("Advanced: cut height", className="small text-muted"),
                _help("Height of the cut on the dendrogram's distance axis (log-rescaled "
                      "1 − similarity). Moving it updates the number of clusters."),
                dcc.Slider(
                    id='threshold-slider',
                    min=0.0,
                    max=1.0,
                    step=0.01,
                    value=config.DEFAULT_DISTANCE_THRESHOLD,
                    marks={i/10: f'{i/10:.1f}' for i in range(0, 11, 2)},
                    tooltip={"placement": "bottom", "always_visible": True}
                ),
            ], className="mb-3"),

            html.Label("Cluster to explore", className="fw-bold"),
            dcc.Dropdown(
                id='cluster-dropdown',
                options=[],
                placeholder="Choose a cluster...",
                className="mb-2"
            ),
            dbc.Button(
                [html.I(className="fas fa-eye me-2"), "View Cluster Details"],
                id='view-cluster-button',
                color="success",
                className="w-100 mb-2",
                disabled=True
            ),

            # Reverse link: ring the function open in Ghidra in Cluster Detail,
            # switching cluster when needed (see the Ghidra reverse-link section).
            html.Hr(className="my-3"),
            dbc.Switch(
                id='ghidra-follow-switch',
                label="Follow Ghidra",
                value=config.GHIDRA_FOLLOW_DEFAULT,
                className="mb-1"
            ),
            html.Small(id='ghidra-follow-status', className="text-muted d-block text-truncate"),
        ])
    ], className="mb-4")


def create_stats_panel():
    """Create statistics panel"""
    return dbc.Card([
        dbc.CardHeader([
            html.H5([
                html.I(className="fas fa-chart-bar me-2"),
                "Clustering Statistics"
            ])
        ]),
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    html.Div(id='stats-display', className="text-center")
                ])
            ])
        ])
    ], className="mb-4")


def create_main_view():
    """Create main visualization area"""
    return dbc.Tabs([
        dbc.Tab(
            label="Dendrogram View",
            tab_id="dendrogram-tab",
            children=[
                dcc.Loading(
                    id="loading-dendrogram",
                    type="default",
                    children=[
                        # Fills the panel and resizes with the window, but keeps a
                        # per-dataset minimum width (set by render_dendrogram) so
                        # labels stay legible; scrolls when the panel is narrower.
                        html.Div(
                            dcc.Graph(
                                id='dendrogram-plot',
                                style={'width': '100%', 'minWidth': '600px'},
                                config={'displayModeBar': True, 'displaylogo': False,
                                        'responsive': True}
                            ),
                            style={'overflowX': 'auto', 'width': '100%'}
                        )
                    ]
                )
            ]
        ),
        dbc.Tab(
            label="Cluster Detail View",
            tab_id="cluster-detail-tab",
            children=[
                dbc.Row([
                    # Left column: Filters
                    dbc.Col([
                        html.H5("Filter Options", className="mt-3 mb-3"),

                        # Color-by control (options adapt to the dataset columns)
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("Color points by", className="fw-bold"),
                                dcc.Dropdown(
                                    id='color-by-dropdown',
                                    options=[{'label': 'Binary', 'value': 'binary_name'}],
                                    value='binary_name',
                                    clearable=False
                                )
                            ])
                        ], className="mb-3"),

                        # Library function filter (needs 'library_name')
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("Library Functions", className="fw-bold"),
                                dbc.Checklist(
                                    id='filter-library-options',
                                    options=[
                                        {'label': 'Exclude library functions', 'value': 'exclude_lib'},
                                        {'label': 'Include only library functions', 'value': 'only_lib'}
                                    ],
                                    value=[]
                                )
                            ])
                        ], id='filter-card-library-options', className="mb-3"),

                        # CAPA rule filter (needs 'rule_name')
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("CAPA Rule Filtering", className="fw-bold"),
                                dbc.Checklist(
                                    id='filter-rule-options',
                                    options=[
                                        {'label': 'Exclude functions with no CAPA rules', 'value': 'exclude_empty_rules'}
                                    ],
                                    value=[]
                                ),
                                html.Div([
                                    dbc.Checklist(
                                        id='filter-rule-nested',
                                        options=[
                                            {'label': 'Also exclude functions matching "contain loop"', 'value': 'exclude_contain_loop'}
                                        ],
                                        value=[],
                                        className="ms-4 mt-2"
                                    )
                                ], id='nested-rule-filter', style={'display': 'none'})
                            ])
                        ], id='filter-card-rule-options', className="mb-3"),

                        # String presence filter (needs 'has_strings')
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("String Content", className="fw-bold"),
                                dbc.Checklist(
                                    id='filter-has_strings',
                                    options=[
                                        {'label': 'Has strings', 'value': True},
                                        {'label': 'No strings', 'value': False}
                                    ],
                                    value=[]
                                )
                            ])
                        ], id='filter-card-strings', className="mb-3"),

                        # External function filter (needs 'has_external_function')
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("External Calls", className="fw-bold"),
                                dbc.Checklist(
                                    id='filter-has_external_function',
                                    options=[
                                        {'label': 'Has external functions', 'value': True},
                                        {'label': 'No external functions', 'value': False}
                                    ],
                                    value=[]
                                )
                            ])
                        ], id='filter-card-external', className="mb-3"),

                        # Binary name filter (always available)
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("Binary Name", className="fw-bold"),
                                dcc.Dropdown(
                                    id='filter-binary-name',
                                    options=[],
                                    multi=True,
                                    placeholder="Select binaries..."
                                )
                            ])
                        ], className="mb-3"),

                        # Function name filter (always available)
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("Function Name", className="fw-bold"),
                                dcc.Dropdown(
                                    id='filter-function-name',
                                    options=[],
                                    multi=True,
                                    placeholder="Select function names...",
                                )
                            ])
                        ], className="mb-3"),

                        # CAPA rule-name dropdown (needs 'rule_name')
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("CAPA Rules", className="fw-bold"),
                                dcc.Dropdown(
                                    id='filter-rule_name',
                                    options=[],
                                    multi=True,
                                    placeholder="Select CAPA rules..."
                                )
                            ])
                        ], id='filter-card-rule-name', className="mb-3"),

                        # Library-name dropdown (needs 'library_name')
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("Library Functions (by name)", className="fw-bold"),
                                dcc.Dropdown(
                                    id='filter-library_name',
                                    options=[],
                                    multi=True,
                                    placeholder="Select library functions..."
                                )
                            ])
                        ], id='filter-card-library-name', className="mb-3"),

                        # Function size range (always available)
                        dbc.Card([
                            dbc.CardBody([
                                html.Label("Function Size Range", className="fw-bold"),
                                dcc.RangeSlider(
                                    id='filter-size',
                                    min=0,
                                    max=10000,
                                    step=10,
                                    value=[0, 10000],
                                    marks={0: '0', 5000: '5K', 10000: '10K'},  # replaced per cluster
                                    tooltip={"placement": "bottom", "always_visible": True}
                                )
                            ])
                        ], className="mb-3"),

                    ], width=3),

                    # Right column: Plot + Stats
                    dbc.Col([
                        dcc.Loading(
                            id="loading-cluster-detail",
                            type="default",
                            delay_show=300,  # overlay patches are quick; no spinner flash
                            children=[
                                dcc.Graph(
                                    id='cluster-detail-plot',
                                    style={'width': '100%', 'height': '600px'},
                                    config={'displayModeBar': True, 'displaylogo': False,
                                            'responsive': True}
                                )
                            ]
                        ),
                        dbc.Card([
                            dbc.CardHeader([
                                html.H5([
                                    html.I(className="fas fa-info-circle me-2"),
                                    "Binary-Level Statistics"
                                ])
                            ]),
                            dbc.CardBody([
                                html.Div(id='binary-stats-display', style={'maxHeight': '300px', 'overflowY': 'auto'})
                            ])
                        ], className="mb-3 mt-3"),
                    ], width=9)
                ], className="mt-3")
            ]
        )
    ], id="main-tabs", active_tab="dendrogram-tab")


# ============================================================================
# Main Layout
# ============================================================================

app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([create_header()], width=12)
    ]),
    
    # Main content
    dbc.Row([
        # Left sidebar - Controls
        dbc.Col([
            create_control_panel(),
            create_stats_panel()
        ], width=3),
        
        # Main visualization area
        dbc.Col([
            create_main_view()
        ], width=9)
    ]),
    
    # Hidden stores for data
    dcc.Store(id='clustering-data-store'),
    dcc.Store(id='cluster-assignments-store'),
    dcc.Store(id='delta-recommendation-store'),  # recommend_delta result for a dataset

    # Ghidra reverse link: what Cluster Detail shows, the last GET /current
    # snapshot, and requests to show another cluster.
    dcc.Store(id='cluster-detail-view-store'),
    dcc.Store(id='ghidra-current-store'),
    dcc.Store(id='ghidra-follow-request'),
    dcc.Interval(
        id='ghidra-poll-interval',
        interval=config.GHIDRA_POLL_INTERVAL_MS,
        disabled=not config.GHIDRA_FOLLOW_DEFAULT,
    ),
    
    # Notification area for Ghidra navigation feedback
    dbc.Toast(
        id="ghidra-navigation-toast",
        header="Ghidra Navigation",
        is_open=False,
        dismissable=True,
        duration=4000,
        icon="info",
        style={"position": "fixed", "top": 66, "right": 10, "width": 350, "zIndex": 9999},
    ),
    
], fluid=True, className="px-4")


# ============================================================================
# Callbacks
# ============================================================================

def _dataset_default(manifest, key, config_default):
    """Per-dataset default from the manifest, falling back to config."""
    value = manifest.get(key)
    return value if value is not None else config_default


@app.callback(
    [Output('clustering-data-store', 'data'),
     Output('stats-display', 'children')],
    [Input('dataset-dropdown', 'value'),
     Input('recompute-button', 'n_clicks')],
    [State('function-threshold-input', 'value'),
     State('binary-threshold-input', 'value')],
    prevent_initial_call=False
)
def update_clustering(dataset_id, n_clicks, function_threshold, binary_threshold):
    """
    Compute the distance matrix for the selected dataset and store it.

    Building the matrix is the expensive step, so it only runs on a dataset
    change or an explicit Recompute. The dendrogram itself is drawn by
    render_dendrogram (cheap, redraws live as the distance slider moves).

    On a dataset change the function/binary thresholds come from the dataset's
    manifest defaults (not the stale input boxes, which apply_dataset_defaults
    updates in parallel); on Recompute they come from the input boxes.
    """
    def _empty(message):
        return None, html.P(message, className="text-danger")

    if not dataset_id:
        return _empty("No dataset selected. Add one under datasets/.")

    processor = dataset_registry.get_processor(dataset_id)
    if processor is None:
        return _empty(f"Could not load dataset '{dataset_id}'.")

    data = processor.load_data()
    if data is None:
        return _empty("No data available. Please check data sources.")

    # Choose thresholds: manifest defaults on dataset-change/initial load,
    # otherwise the current values in the input boxes.
    triggered = [t['prop_id'].split('.')[0] for t in callback_context.triggered]
    use_defaults = (not triggered) or ('dataset-dropdown' in triggered)
    manifest = dataset_registry.get_manifest(dataset_id)
    if use_defaults:
        function_threshold = _dataset_default(
            manifest, 'default_function_threshold', config.DEFAULT_FUNCTION_THRESHOLD)
        binary_threshold = _dataset_default(
            manifest, 'default_binary_threshold', config.DEFAULT_BINARY_THRESHOLD)
    else:
        function_threshold = function_threshold if function_threshold is not None else config.DEFAULT_FUNCTION_THRESHOLD
        # The input shows the binary threshold as a percentage.
        binary_threshold = (binary_threshold / 100 if binary_threshold is not None
                            else config.DEFAULT_BINARY_THRESHOLD)

    dist_matrix = processor.generate_distance_matrix(
        data,
        function_threshold=function_threshold,
        binary_threshold=binary_threshold
    )

    labels = processor.get_binary_labels()
    avclass_tags = processor.get_avclass_tags()

    n_binaries = len(labels)
    n_unique_tags = len(set(avclass_tags.values())) if avclass_tags else 0

    stats_display = [
        html.Div([
            html.H3(str(n_binaries), className="text-primary mb-0"),
            html.P("Total Binaries", className="text-muted small")
        ], className="mb-3"),
        html.Div([
            html.H3(str(n_unique_tags), className="text-success mb-0"),
            html.P("Unique Tags", className="text-muted small")
        ], className="mb-3"),
    ]

    clustering_data = {
        'dataset_id': dataset_id,
        'dist_matrix': dist_matrix.tolist(),
        'labels': labels,
        'function_threshold': function_threshold,
        'binary_threshold': binary_threshold
    }

    return clustering_data, stats_display


@app.callback(
    [Output('dendrogram-plot', 'figure'),
     Output('dendrogram-plot', 'style')],
    [Input('clustering-data-store', 'data'),
     Input('threshold-slider', 'value')]
)
def render_dendrogram(clustering_data, distance_threshold):
    """
    Draw the dendrogram from the stored distance matrix. Redraws live when the
    Distance Threshold slider moves (cut line, cluster coloring, and the
    left-to-right cluster-number labels) without recomputing the matrix.

    The graph fills its panel responsively but is given a per-dataset minimum
    width so labels stay legible; the wrapper scrolls when the panel is narrower.
    """
    if clustering_data is None:
        raise PreventUpdate

    dataset_id = clustering_data.get('dataset_id')
    dist_matrix = np.array(clustering_data['dist_matrix'])
    labels = clustering_data['labels']

    processor = dataset_registry.get_processor(dataset_id)
    avclass_tags = processor.get_avclass_tags() if processor is not None else {}

    if distance_threshold is None:
        distance_threshold = config.DEFAULT_DISTANCE_THRESHOLD

    manifest = dataset_registry.get_manifest(dataset_id)
    avclass_threshold = _dataset_default(
        manifest, 'avclass_threshold', config.LIMIT_RELEVANT_CLUSTERS)

    dataset_name = next(
        (d['name'] for d in DATASETS if d['id'] == dataset_id), dataset_id
    )

    # Left-to-right numbered clusters at the current cut (labels on the plot).
    cluster_groups = (
        processor.get_ordered_clusters(dist_matrix, distance_threshold, labels)
        if processor is not None else None
    )

    n = len(labels)
    min_width = int(min(config.DENDROGRAM_MAX_WIDTH,
                        max(config.DENDROGRAM_MIN_WIDTH,
                            config.DENDROGRAM_PX_PER_BINARY * n + 200)))

    fig = dendrogram_viz.create_dendrogram(
        dist_matrix=dist_matrix,
        labels=labels,
        avclass_tags=avclass_tags,
        title=f"{dataset_name} — {n} binaries",
        height=config.DENDROGRAM_HEIGHT,
        cut_threshold=distance_threshold,
        avclass_threshold=avclass_threshold,
        cluster_groups=cluster_groups,
    )
    style = {'width': '100%', 'minWidth': f'{min_width}px'}
    return fig, style


@app.callback(
    [Output('function-threshold-input', 'value'),
     Output('binary-threshold-input', 'value'),
     Output('threshold-slider', 'value')],
    Input('dataset-dropdown', 'value'),
    prevent_initial_call=False
)
def apply_dataset_defaults(dataset_id):
    """Populate the threshold controls from the selected dataset's manifest
    defaults (falling back to config) whenever the dataset changes."""
    manifest = dataset_registry.get_manifest(dataset_id) if dataset_id else {}
    return (
        _dataset_default(manifest, 'default_function_threshold', config.DEFAULT_FUNCTION_THRESHOLD),
        round(100 * _dataset_default(manifest, 'default_binary_threshold',
                                     config.DEFAULT_BINARY_THRESHOLD), 4),  # shown in %
        _dataset_default(manifest, 'default_distance_threshold', config.DEFAULT_DISTANCE_THRESHOLD),
    )


def _linkage(clustering_data):
    """Average-linkage tree of the stored distance matrix: the same tree the
    dendrogram draws and get_ordered_clusters cuts."""
    return linkage(squareform(np.array(clustering_data['dist_matrix'])), method='average')


def _cut_for_clusters(Z, k):
    """Cut height giving k clusters: midway between the merges that leave k
    groups (ties can make some k unreachable; the caller reports the real count)."""
    heights = np.sort(Z[:, 2])
    n = len(heights) + 1
    k = int(min(max(k, 1), n))
    if k == 1:
        return float(heights[-1])
    if k == n:
        return float(heights[0] / 2)
    return float((heights[n - k - 1] + heights[n - k]) / 2)


@app.callback(
    [Output('n-clusters-slider', 'max'),
     Output('n-clusters-slider', 'marks'),
     Output('n-clusters-slider', 'value'),
     Output('threshold-slider', 'value', allow_duplicate=True),
     Output('threshold-slider', 'max'),
     Output('n-clusters-readout', 'children')],
    [Input('n-clusters-slider', 'value'),
     Input('threshold-slider', 'value'),
     Input('clustering-data-store', 'data')],
    prevent_initial_call=True
)
def sync_cluster_count(n_clusters, cut, clustering_data):
    """Keep "Number of clusters" and the (advanced) cut height in step: moving
    either one sets the other; new similarity data keeps the cut height."""
    if not clustering_data or len(clustering_data.get('labels', [])) < 2:
        raise PreventUpdate
    Z = _linkage(clustering_data)
    n = len(clustering_data['labels'])
    if callback_context.triggered_id == 'n-clusters-slider':
        cut = _cut_for_clusters(Z, n_clusters)
        cut_out = cut
    else:
        cut = cut if cut is not None else config.DEFAULT_DISTANCE_THRESHOLD
        cut_out = no_update
    actual = int(fcluster(Z, cut, criterion='distance').max())
    cut_max = max(1.0, round(float(Z[:, 2].max()) * 1.05, 2))
    return (n, {1: '1', n: str(n)}, actual, cut_out, cut_max,
            f"({actual} of {n} binaries · cut {cut:.3f})")


@app.callback(
    [Output('cluster-dropdown', 'options'),
     Output('cluster-assignments-store', 'data')],
    [Input('threshold-slider', 'value'),
     Input('clustering-data-store', 'data')]
)
def update_cluster_assignments(threshold, clustering_data):
    """
    Rebuild the cluster list at the current distance threshold.

    Clusters are numbered left-to-right (matching the numbers drawn on the
    dendrogram), and each dropdown entry shows the dominant avclass tag and a
    few member binaries so a cluster is easy to identify.
    """
    if clustering_data is None:
        raise PreventUpdate

    dist_matrix = np.array(clustering_data['dist_matrix'])
    labels = clustering_data['labels']

    processor = dataset_registry.get_processor(clustering_data.get('dataset_id'))
    if processor is None:
        raise PreventUpdate

    ordered = processor.get_ordered_clusters(dist_matrix, threshold, labels)
    avclass_tags = processor.get_avclass_tags()

    options = []
    assignments = {}
    for cluster in ordered:
        number = cluster['number']
        binaries = cluster['binaries']
        assignments[str(number)] = binaries

        # Dominant avclass tag among the cluster's binaries (if any).
        tags = [avclass_tags.get(b) for b in binaries if avclass_tags.get(b)]
        dominant = Counter(tags).most_common(1)[0][0] if tags else None

        preview = ", ".join(binaries[:2]) + ("…" if len(binaries) > 2 else "")
        label = f"C{number}"
        if dominant:
            label += f" · {dominant}"
        label += f" ({len(binaries)}): {preview}"
        options.append({'label': label, 'value': str(number), 'title': ", ".join(binaries)})

    return options, assignments


@app.callback(
    Output('view-cluster-button', 'disabled'),
    Input('cluster-dropdown', 'value')
)
def enable_view_button(selected_cluster):
    """Enable/disable view button based on cluster selection"""
    return selected_cluster is None


@app.callback(
    [Output('cluster-dropdown', 'value', allow_duplicate=True),
     Output('main-tabs', 'active_tab', allow_duplicate=True)],
    Input('dataset-dropdown', 'value'),
    prevent_initial_call=True
)
def reset_view_on_dataset_change(dataset_id):
    """Reset the view when the dataset changes: clear the selected cluster and
    return to the dendrogram tab. update_clustering re-fires in parallel to
    reload data and repopulate the dendrogram + cluster options."""
    return None, "dendrogram-tab"


# Filter cards that depend on optional enrichment columns. A card is shown only
# when the selected dataset actually has the column it filters on; otherwise it
# is hidden so the minimal public format doesn't show dead controls.
OPTIONAL_FILTER_CARDS = [
    ('filter-card-library-options', 'library_name'),
    ('filter-card-rule-options', 'rule_name'),
    ('filter-card-strings', 'has_strings'),
    ('filter-card-external', 'has_external_function'),
    ('filter-card-rule-name', 'rule_name'),
    ('filter-card-library-name', 'library_name'),
]


@app.callback(
    [Output(card_id, 'style') for card_id, _ in OPTIONAL_FILTER_CARDS],
    Input('dataset-dropdown', 'value')
)
def toggle_optional_filters(dataset_id):
    """Show each optional filter card only if its column exists in the dataset."""
    columns = set(dataset_registry.get_columns(dataset_id))
    return [
        {} if column in columns else {'display': 'none'}
        for _, column in OPTIONAL_FILTER_CARDS
    ]


# Candidate columns the scatter can be colored by, with display labels. Only
# those present in the selected dataset are offered.
COLOR_BY_CANDIDATES = [
    ('binary_name', 'Binary'),
    ('name', 'Function name'),
    ('size', 'Function size'),
    ('rule_name', 'CAPA rule'),
    ('library_name', 'Library'),
    ('has_strings', 'Has strings'),
    ('has_external_function', 'Has external call'),
]


@app.callback(
    [Output('color-by-dropdown', 'options'),
     Output('color-by-dropdown', 'value')],
    Input('dataset-dropdown', 'value')
)
def update_color_by_options(dataset_id):
    """Offer only the color-by columns the selected dataset actually has."""
    columns = set(dataset_registry.get_columns(dataset_id))
    options = [{'label': label, 'value': col}
               for col, label in COLOR_BY_CANDIDATES if col in columns]
    if not options:
        options = [{'label': 'Binary', 'value': 'binary_name'}]
    return options, 'binary_name'


@app.callback(
    Output('nested-rule-filter', 'style'),
    Input('filter-rule-options', 'value')
)
def toggle_nested_rule_filter(rule_options):
    """Show nested rule filter only when 'exclude_empty_rules' is selected"""
    if rule_options and 'exclude_empty_rules' in rule_options:
        return {'display': 'block'}
    return {'display': 'none'}


def _compact(n):
    """1234 -> '1.2K', 2500000 -> '2.5M'."""
    for div, unit in ((1e6, 'M'), (1e3, 'K')):
        if abs(n) >= div:
            return f"{n / div:.1f}".rstrip('0').rstrip('.') + unit
    return f"{n:g}"


def _size_marks_step(lo, hi):
    """Four labelled marks across the size range (no auto-generated ticks) and
    a step of ~1/200 of it, so the slider stays readable for any cluster."""
    lo, hi = float(lo), float(hi)
    if hi <= lo:
        return {lo: _compact(lo)}, 1
    marks = {round(lo + (hi - lo) * i / 3): _compact(round(lo + (hi - lo) * i / 3)) for i in range(4)}
    return marks, max(1, round((hi - lo) / 200))


@app.callback(
    [Output('filter-binary-name', 'options'),
     Output('filter-function-name', 'options'),
     Output('filter-rule_name', 'options'),
     Output('filter-library_name', 'options'),
     Output('filter-size', 'min'),
     Output('filter-size', 'max'),
     Output('filter-size', 'value'),
     Output('filter-size', 'marks'),
     Output('filter-size', 'step'),
     Output('filter-binary-name', 'value'),
     Output('filter-function-name', 'value')],
    [Input('cluster-dropdown', 'value')],
    [State('cluster-assignments-store', 'data'),
     State('dataset-dropdown', 'value')]
)
def update_filter_options(selected_cluster, cluster_assignments, dataset_id):
    """
    Update filter dropdown options based on selected cluster data.

    Binary/function selections name members of the previous cluster, so they
    are cleared on a cluster change (manual or "Follow Ghidra"); rule/library
    filters are cluster-independent and kept.
    """
    if selected_cluster is None or cluster_assignments is None:
        # Return empty options
        return [], [], [], [], 0, 10000, [0, 10000], *_size_marks_step(0, 10000), [], []

    selected_cluster = str(selected_cluster)
    cluster_binaries = cluster_assignments.get(selected_cluster, [])

    if not cluster_binaries:
        return [], [], [], [], 0, 10000, [0, 10000], *_size_marks_step(0, 10000), [], []

    processor = dataset_registry.get_processor(dataset_id)
    if processor is None:
        return [], [], [], [], 0, 10000, [0, 10000], *_size_marks_step(0, 10000), [], []

    # Get data for these binaries
    cluster_data = processor.get_cluster_data(cluster_binaries)
    
    # Binary names
    binary_options = [{'label': b, 'value': b, 'title': b}
                      for b in sorted(cluster_data['binary_name'].unique())]
    
    # Function names
    if 'name' in cluster_data.columns:
        unique_functions = cluster_data['name'].dropna().unique().tolist()
        function_options = [{'label': f, 'value': f, 'title': f} for f in sorted(unique_functions)]
    else:
        function_options = []
    
    # Rule names
    if 'rule_name' in cluster_data.columns:
        unique_rules = cluster_data['rule_name'].dropna().unique().tolist()
        rule_options = [{'label': r, 'value': r, 'title': r} for r in sorted(unique_rules)]
    else:
        rule_options = []
    
    # Library names
    if 'library_name' in cluster_data.columns:
        unique_libs = cluster_data['library_name'].dropna().unique().tolist()
        lib_options = [{'label': l, 'value': l, 'title': l} for l in sorted(unique_libs)]
    else:
        lib_options = []
    
    # Size range
    if 'size' in cluster_data.columns:
        size_min = float(cluster_data['size'].min())
        size_max = float(cluster_data['size'].max())
        size_value = [size_min, size_max]
    else:
        size_min, size_max, size_value = 0, 10000, [0, 10000]
    
    return (binary_options, function_options, rule_options, lib_options,
            size_min, size_max, size_value, *_size_marks_step(size_min, size_max), [], [])


@app.callback(
    [Output('cluster-detail-plot', 'figure'),
     Output('binary-stats-display', 'children'),
     Output('main-tabs', 'active_tab'),
     Output('cluster-detail-view-store', 'data')],
    [Input('view-cluster-button', 'n_clicks'),
     Input('ghidra-follow-request', 'data')],
    [State('cluster-dropdown', 'value'),
     State('cluster-assignments-store', 'data'),
     State('dataset-dropdown', 'value'),
     State('color-by-dropdown', 'value'),
     State('ghidra-current-store', 'data'),
     State('ghidra-follow-switch', 'value')]
)
def view_cluster_details(n_clicks, follow_request, selected_cluster, cluster_assignments,
                         dataset_id, color_by, ghidra_current, follow):
    """
    Display detailed view of selected cluster with binary statistics.

    Also runs when "Follow Ghidra" switched cluster (ghidra-follow-request):
    then it only refreshes the statistics. sync_ghidra_highlight already set
    cluster-dropdown, which redraws the plot via update_filter_options ->
    apply_filters; drawing it here too would race that chain. The tab is left
    alone so Ghidra never pulls the user off what they are looking at.
    """
    follow_triggered = callback_context.triggered_id == 'ghidra-follow-request'
    if follow_triggered:
        if not follow_request:
            raise PreventUpdate
        selected_cluster = follow_request['cluster']
    elif n_clicks is None:
        raise PreventUpdate
    if selected_cluster is None or cluster_assignments is None:
        raise PreventUpdate

    selected_cluster = str(selected_cluster)
    # Get binaries in selected cluster
    cluster_binaries = cluster_assignments.get(selected_cluster, [])

    if not cluster_binaries:
        empty_fig = go.Figure()
        empty_fig.add_annotation(
            text="No binaries in selected cluster",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False
        )
        if follow_triggered:
            return no_update, html.P("No data available", className="text-muted"), \
                no_update, no_update
        return (empty_fig, html.P("No data available", className="text-muted"),
                "cluster-detail-tab", None)

    processor = dataset_registry.get_processor(dataset_id)
    if processor is None:
        raise PreventUpdate

    # Get data for these binaries
    cluster_data = processor.get_cluster_data(cluster_binaries)

    # Create plot (ringing the function open in Ghidra if it is shown)
    if follow_triggered:
        fig = view = no_update
    else:
        keys = _ghidra_keys(cluster_data)
        fig = binary_viz.create_binary_plot(
            cluster_data,
            binary_names=cluster_binaries,
            color_by=color_by or 'binary_name',
            title=f"Cluster C{selected_cluster} - Binary Functions ({len(cluster_data)} functions)",
            highlight=_ghidra_overlay_point(processor, ghidra_current, follow, keys),
            uirevision=_view_revision(dataset_id, cluster_binaries),
        )
        view = _cluster_view(fig, dataset_id, selected_cluster, cluster_binaries, keys)

    # Generate binary statistics using the data processor method
    binary_stats = processor.get_binary_statistics(cluster_binaries)
    stats_components = []
    
    for binary_name in sorted(cluster_binaries):
        stats = binary_stats.get(binary_name)
        
        if not stats:
            continue
        
        # Extract statistics
        file_size = stats['file_size']
        total_functions = stats['total_functions']
        avclass_tag = stats['avclass_tag']
        capa_count = stats['capa_functions']
        lib_count = stats['library_functions']
        
        # Format file size
        if file_size is not None and isinstance(file_size, (int, float)):
            if file_size > 1024 * 1024:
                size_display = f"{file_size / (1024 * 1024):.2f} MB"
            elif file_size > 1024:
                size_display = f"{file_size / 1024:.2f} KB"
            else:
                size_display = f"{file_size:.0f} bytes"
        else:
            size_display = "N/A"
        
        # Create card for this binary
        binary_card = dbc.Card([
            dbc.CardHeader([
                html.Strong(binary_name, title=binary_name, className="d-block text-truncate")
            ]),
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.Small("File Size:", className="text-muted d-block"),
                        html.Strong(size_display)
                    ], width=6),
                    dbc.Col([
                        html.Small("Functions:", className="text-muted d-block"),
                        html.Strong(str(total_functions))
                    ], width=6)
                ], className="mb-2"),
                dbc.Row([
                    dbc.Col([
                        html.Small("AVClass:", className="text-muted d-block"),
                        dbc.Badge(avclass_tag, color="info", title=str(avclass_tag),
                                  className="me-1 mw-100 text-truncate")
                    ], width=12)
                ], className="mb-2"),
                dbc.Row([
                    dbc.Col([
                        html.Small("CAPA Rules:", className="text-muted d-block"),
                        html.Strong(str(capa_count), className="text-success")
                    ], width=6),
                    dbc.Col([
                        html.Small("Libraries:", className="text-muted d-block"),
                        html.Strong(str(lib_count), className="text-primary")
                    ], width=6)
                ])
            ])
        ], className="mb-2")
        
        stats_components.append(binary_card)
    
    if not stats_components:
        stats_components = [html.P("No statistics available", className="text-muted")]
    
    return fig, stats_components, no_update if follow_triggered else "cluster-detail-tab", view


@app.callback(
    [Output('cluster-detail-plot', 'figure', allow_duplicate=True),
     Output('cluster-detail-view-store', 'data', allow_duplicate=True)],
    [Input('filter-size', 'value'),
     Input('filter-binary-name', 'value'),
     Input('filter-function-name', 'value'),
     Input('filter-rule_name', 'value'),
     Input('filter-library_name', 'value'),
     Input('filter-library-options', 'value'),
     Input('filter-rule-options', 'value'),
     Input('filter-rule-nested', 'value'),
     Input('filter-has_strings', 'value'),
     Input('filter-has_external_function', 'value'),
     Input('color-by-dropdown', 'value')],
    [State('cluster-dropdown', 'value'),
     State('cluster-assignments-store', 'data'),
     State('dataset-dropdown', 'value'),
     State('ghidra-current-store', 'data'),
     State('ghidra-follow-switch', 'value')],
    prevent_initial_call=True
)
def apply_filters(size_range, selected_binaries, selected_functions, selected_rules, selected_libs,
                  library_options, rule_options, rule_nested,
                  has_strings_filter, has_ext_func_filter, color_by,
                  selected_cluster, cluster_assignments, dataset_id, ghidra_current, follow):
    """
    Apply filters to cluster detail view (enhanced with new filters)
    """
    if selected_cluster is None or cluster_assignments is None:
        raise PreventUpdate

    selected_cluster = str(selected_cluster)
    cluster_binaries = cluster_assignments.get(selected_cluster, [])

    if not cluster_binaries:
        raise PreventUpdate

    processor = dataset_registry.get_processor(dataset_id)
    if processor is None:
        raise PreventUpdate

    # Get base cluster data
    cluster_data = processor.get_cluster_data(cluster_binaries)
    filtered_data = cluster_data.copy()
    initial_count = len(filtered_data)
    
    # Apply size filter
    if size_range and 'size' in filtered_data.columns:
        min_size, max_size = size_range
        filtered_data = filtered_data[
            (filtered_data['size'] >= min_size) & 
            (filtered_data['size'] <= max_size)
        ]
    
    # Apply binary name filter
    if selected_binaries:
        filtered_data = filtered_data[filtered_data['binary_name'].isin(selected_binaries)]
    
    # Apply function name filter (NEW)
    if selected_functions and 'name' in filtered_data.columns:
        filtered_data = filtered_data[filtered_data['name'].isin(selected_functions)]
    
    # Apply rule name filter
    if selected_rules and 'rule_name' in filtered_data.columns:
        filtered_data = filtered_data[filtered_data['rule_name'].isin(selected_rules)]
    
    # Apply library name filter
    if selected_libs and 'library_name' in filtered_data.columns:
        filtered_data = filtered_data[filtered_data['library_name'].isin(selected_libs)]
    
    # Apply library function filters (NEW)
    if library_options and 'library_name' in filtered_data.columns:
        if 'exclude_lib' in library_options and 'only_lib' not in library_options:
            # Filter OUT library functions (keep only where library_name is empty/null)
            filtered_data = filtered_data[filtered_data['library_name'].isna() | (filtered_data['library_name'] == '')]
        elif 'only_lib' in library_options and 'exclude_lib' not in library_options:
            # Filter IN only library functions (keep only where library_name is not empty)
            filtered_data = filtered_data[filtered_data['library_name'].notna() & (filtered_data['library_name'] != '')]
        # If both are selected, they cancel each other out (no filtering)
    
    # Apply rule filters (NEW)
    if rule_options and 'rule_name' in filtered_data.columns:
        if 'exclude_empty_rules' in rule_options:
            # Filter out rows where rule_name is empty
            filtered_data = filtered_data[filtered_data['rule_name'].notna() & (filtered_data['rule_name'] != '')]
            
            # Check nested filter for "contain loop"
            if rule_nested and 'exclude_contain_loop' in rule_nested:
                # Also exclude "contain loop"
                filtered_data = filtered_data[filtered_data['rule_name'] != 'contain loop']
    
    # Apply boolean filters (only if exactly one option selected, webapp.py pattern)
    if has_strings_filter and len(has_strings_filter) == 1 and 'has_strings' in filtered_data.columns:
        filtered_data = filtered_data[filtered_data['has_strings'] == has_strings_filter[0]]
    
    if has_ext_func_filter and len(has_ext_func_filter) == 1 and 'has_external_function' in filtered_data.columns:
        filtered_data = filtered_data[filtered_data['has_external_function'] == has_ext_func_filter[0]]
    
    # Create updated plot (same uirevision as the unfiltered view keeps zoom)
    keys = _ghidra_keys(filtered_data)
    fig = binary_viz.create_binary_plot(
        filtered_data,
        binary_names=cluster_binaries,
        color_by=color_by or 'binary_name',
        title=f"Cluster C{selected_cluster} - Filtered View ({len(filtered_data)} of {initial_count} functions)",
        highlight=_ghidra_overlay_point(processor, ghidra_current, follow, keys),
        uirevision=_view_revision(dataset_id, cluster_binaries),
    )

    return fig, _cluster_view(fig, dataset_id, selected_cluster, cluster_binaries, keys)


@app.callback(
    [Output('ghidra-navigation-toast', 'is_open'),
     Output('ghidra-navigation-toast', 'children'),
     Output('ghidra-navigation-toast', 'icon')],
    [Input('cluster-detail-plot', 'clickData')],
    prevent_initial_call=True
)
def navigate_to_function_in_ghidra(clickData):
    """
    Handle click events on the cluster detail plot and navigate to function in Ghidra.
    
    This callback:
    1. Extracts function address/name from clicked point
    2. Sends navigation request to Ghidra server
    3. Shows toast notification with result
    """
    if not clickData:
        raise PreventUpdate
    
    try:
        # Extract point data
        point = clickData['points'][0]
        
        # Get customdata: [address, function_name, binary_name]
        customdata = point.get('customdata')
        
        if not customdata or len(customdata) < 3:
            return True, "⚠️ Could not extract function information from click", "warning"
        
        address, function_name, binary_name = customdata[0], customdata[1], customdata[2]
        
        # Check if Ghidra server is available (with quick timeout)
        if not ghidra_client.check_server():
            return (
                True,
                html.Div([
                    html.P("❌ Ghidra server not available", className="mb-1"),
                    html.Small(
                        "Make sure the MapterBridge extension is running in Ghidra "
                        "(Tools → MAPTER → Navigation Server)",
                        className="text-muted"
                    )
                ]),
                "danger"
            )
        
        # Send navigation request
        result = ghidra_client.navigate_to_function(
            address=address if address and str(address) != 'None' else None,
            name=function_name if function_name and str(function_name) != 'None' else None,
            binary_name=binary_name
        )
        
        # Format response
        if result.get('success'):
            message = html.Div([
                html.P(f"✓ Navigated to function in Ghidra", className="mb-1"),
                html.Small(f"Function: {result.get('function_name', 'N/A')}", className="d-block"),
                html.Small(f"Address: {result.get('address', 'N/A')}", className="d-block"),
                html.Small(f"Binary: {result.get('binary', 'N/A')}", className="text-muted")
            ])
            return True, message, "success"
        else:
            error_msg = result.get('error', 'Unknown error')
            message = html.Div([
                html.P("❌ Navigation failed", className="mb-1"),
                html.Small(error_msg, className="text-danger")
            ])
            return True, message, "danger"
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return (
            True,
            html.Div([
                html.P("❌ Error during navigation", className="mb-1"),
                html.Small(str(e), className="text-danger")
            ]),
            "danger"
        )


# ============================================================================
# δ recommendation (recommend_delta.py)
# ============================================================================
#
# δ is the Function Similarity Threshold: the radius within which a function of
# one binary counts as close to a function of another (find_similar_groups'
# distance_upper_bound). recommend_delta derives a search range and candidate
# radii from the distances between functions of unrelated binaries.

@functools.lru_cache(maxsize=8)
def _delta_recommendation(dataset_id):
    """recommend_delta.recommend() for a dataset (deterministic seed, ~2 s), cached."""
    processor = dataset_registry.get_processor(dataset_id)
    if processor is None or processor.data is None:
        raise ValueError(f"dataset {dataset_id!r} not loaded")
    coords, binary_names = recommend_delta.from_dataframe(processor.data)
    return recommend_delta.recommend(coords, binary_names)


@app.callback(
    Output('delta-recommendation-store', 'data'),
    Input('suggest-delta-button', 'n_clicks'),
    State('dataset-dropdown', 'value'),
    prevent_initial_call=True
)
def suggest_delta(n_clicks, dataset_id):
    """Compute (or reuse) the δ recommendation for the selected dataset."""
    if not dataset_id:
        raise PreventUpdate
    try:
        rec = _delta_recommendation(dataset_id)
    except Exception as e:  # noqa: BLE001
        logger.error(f"δ recommendation failed for {dataset_id}: {e}")
        return {'dataset_id': dataset_id, 'error': str(e)}
    r = rec['range']
    logger.info(f"δ recommendation for {dataset_id}: p{r['lower_percentile']}-p{r['upper_percentile']}"
                f" = {r['lower_delta']:.4g}-{r['upper_delta']:.4g}")
    return {'dataset_id': dataset_id, 'rec': rec}


@app.callback(
    Output('delta-suggestion', 'children'),
    [Input('delta-recommendation-store', 'data'),
     Input('function-threshold-input', 'value'),
     Input('dataset-dropdown', 'value')]
)
def render_delta_suggestion(stored, delta, dataset_id):
    """Search range, clickable candidates and where the current δ falls."""
    if not stored or stored.get('dataset_id') != dataset_id:
        return None  # nothing computed yet, or for another dataset
    if stored.get('error'):
        return html.Small(f"Could not suggest δ: {stored['error']}", className="text-danger")

    rec = stored['rec']
    r = rec['range']
    candidates = [
        dbc.Button(
            f"p{c['percentile']}: {c['delta']:.3g}",
            id={'type': 'delta-candidate', 'index': i},
            size="sm", color="primary", outline=True, className="me-1 mb-1",
            title=(f"95% CI {c['ci95'][0]:.3g} – {c['ci95'][1]:.3g}" if 'ci95' in c else None),
        )
        for i, c in enumerate(rec['candidates'])
    ]
    parts = [
        html.Small(
            f"Search range p{r['lower_percentile']}–p{r['upper_percentile']}: "
            f"{r['lower_delta']:.3g} – {r['upper_delta']:.3g} "
            f"(identical code {100 * rec['zero_share']:.1f}%). Candidates:",
            className="d-block text-muted mb-1"),
        html.Div(candidates),
    ]
    if isinstance(delta, (int, float)) and delta > 0:
        where = recommend_delta.in_range(delta, rec)
        pos = recommend_delta.position_of(delta, rec)
        pos_text = f"p{pos:.0f}, " if pos is not None else ""
        level = "success" if where == "inside" else "warning"
        parts.append(html.Small(f"Current δ = {delta:g}: {pos_text}{where} the range",
                                className=f"d-block text-{level}"))
    parts.append(html.Small(
        "Choose among the candidates with known relations or by inspecting the dendrogram "
        "(too large a δ merges binaries into a few groups), then Recompute Clusters.",
        className="d-block text-muted mt-1"))
    return html.Div(parts)


@app.callback(
    Output('function-threshold-input', 'value', allow_duplicate=True),
    Input({'type': 'delta-candidate', 'index': ALL}, 'n_clicks'),
    State('delta-recommendation-store', 'data'),
    prevent_initial_call=True
)
def apply_delta_candidate(n_clicks, stored):
    """Clicking a candidate puts its radius into the Function Similarity Threshold."""
    trigger = callback_context.triggered_id
    if not trigger or not any(n_clicks) or not stored or 'rec' not in stored:
        raise PreventUpdate  # buttons just (re)rendered
    candidate = stored['rec']['candidates'][trigger['index']]
    return float(f"{candidate['delta']:.4g}")


# ============================================================================
# Ghidra reverse link (Ghidra cursor -> Cluster Detail highlight)
# ============================================================================
#
# poll_ghidra_current asks MapterBridge for GET /current every
# GHIDRA_POLL_INTERVAL_MS and stores the snapshot only when it changes.
# sync_ghidra_highlight reacts to that change: it moves the ring overlay (the
# last trace of the scatter, patched in place), or selects the cluster holding
# the function (the cluster-dropdown change redraws Cluster Detail). Points are matched on
# (binary_name, int(offset)); the Ghidra program name is the full hash.

def _ghidra_key(binary_name, offset):
    """Join key between a scatter point and Ghidra, or None if offset isn't hex."""
    value = parse_hex_offset(offset)
    return None if value is None or binary_name is None else f"{binary_name}|{value}"


def _ghidra_keys(data):
    """Join keys of every function in a (displayed) dataframe."""
    if data is None or len(data) == 0 or 'offset' not in data.columns:
        return []
    keys = (_ghidra_key(b, o) for b, o in zip(data['binary_name'], data['offset']))
    return [k for k in keys if k]


def _cluster_view(fig, dataset_id, cluster, cluster_binaries, keys):
    """What Cluster Detail shows, for sync_ghidra_highlight; None if the figure
    has no overlay trace to patch (empty/error plots)."""
    if not fig.data or fig.data[-1].name != GHIDRA_OVERLAY_NAME:
        return None
    return {'dataset_id': dataset_id, 'cluster': str(cluster),
            'binaries': list(cluster_binaries), 'keys': keys}


def _view_revision(dataset_id, cluster_binaries):
    """Plotly uirevision for a Cluster Detail view: keyed on the binaries shown
    (cluster numbers change with the threshold), so zoom survives filter
    changes and ring updates but resets for a different set of binaries."""
    digest = hashlib.sha1("\n".join(sorted(cluster_binaries)).encode()).hexdigest()[:12]
    return f"{dataset_id}:{digest}"


def _short_program(name, width=16):
    name = str(name)
    return name if len(name) <= width else name[:width] + "…"


def _resolve_ghidra_function(processor, current):
    """
    Map a GET /current snapshot to a dataset function.

    Returns:
        (point, reason): point is {'key', 'binary_name', 'offset', 'name',
        'x', 'y'} or None, in which case reason says why for the status line.
    """
    if not current or not current.get('available'):
        return None, "Ghidra not reachable (is MapterBridge running?)"
    program = current.get('program')
    if not program:
        return None, "No program open in Ghidra"
    entry = parse_hex_offset(current.get('entry_address'))
    if entry is None:
        if current.get('function_name'):
            # MapterBridge only publishes default-address-space entries.
            return None, f"{current['function_name']} is outside the main address space"
        return None, f"Ghidra cursor is not in a function ({_short_program(program)})"
    if processor is None:
        return None, "Dataset not loaded"

    data = processor.data
    binary_name, candidates = match_binary_name(
        program, data['binary_name'].dropna().unique(), current.get('program_sha256'))
    if binary_name is None:
        if candidates:
            return None, (f"{_short_program(program)} matches several binaries: "
                          f"{', '.join(sorted(candidates))}")
        return None, f"{_short_program(program)} is not in this dataset"

    rows = data[data['binary_name'] == binary_name]
    hits = rows[rows['offset'].map(parse_hex_offset) == entry]
    label = current.get('function_name') or current.get('entry_address')
    if hits.empty:
        return None, f"{label} ({binary_name}) is not in this dataset"
    row = hits.iloc[0]
    name = row['name'] if 'name' in row and isinstance(row['name'], str) else label
    return {
        'key': _ghidra_key(binary_name, row['offset']),
        'binary_name': binary_name,
        'offset': row['offset'],
        'name': name,
        'x': float(row['x']),
        'y': float(row['y']),
    }, None


def _ghidra_overlay_point(processor, current, follow, keys):
    """Point to ring when (re)building the scatter, if it is among `keys`."""
    if not follow:
        return None
    point, _ = _resolve_ghidra_function(processor, current)
    return point if point and point['key'] in set(keys) else None


def _cluster_of(cluster_assignments, binary_name):
    """Cluster number (str) holding binary_name at the current threshold."""
    for number, binaries in (cluster_assignments or {}).items():
        if binary_name in binaries:
            return number
    return None


def _follow_status(text, level="muted"):
    return html.Span(text, title=text, className=f"text-{level}")


@app.callback(
    [Output('ghidra-poll-interval', 'disabled'),
     Output('ghidra-current-store', 'data', allow_duplicate=True)],
    Input('ghidra-follow-switch', 'value'),
    prevent_initial_call=True
)
def toggle_ghidra_poll(follow):
    """Poll Ghidra only while "Follow Ghidra" is on. Switching it on drops the
    snapshot from before it was off, so nothing stale is followed and the next
    poll always stores (and acts on) a fresh one."""
    return not follow, (None if follow else no_update)


@app.callback(
    Output('ghidra-current-store', 'data'),
    Input('ghidra-poll-interval', 'n_intervals'),
    State('ghidra-current-store', 'data'),
    prevent_initial_call=True
)
def poll_ghidra_current(n_intervals, previous):
    """Fetch GET /current; update the store only when the snapshot changed."""
    current = ghidra_client.get_current(timeout=config.GHIDRA_POLL_TIMEOUT)
    snapshot = {'available': current is not None, **(current or {})}
    if snapshot == previous:
        raise PreventUpdate
    logger.debug(f"Ghidra cursor changed: {snapshot}")
    return snapshot


@app.callback(
    [Output('cluster-detail-plot', 'figure', allow_duplicate=True),
     Output('ghidra-follow-status', 'children'),
     Output('cluster-dropdown', 'value', allow_duplicate=True),
     Output('ghidra-follow-request', 'data')],
    [Input('ghidra-current-store', 'data'),
     Input('ghidra-follow-switch', 'value'),
     Input('cluster-detail-view-store', 'data')],
    [State('dataset-dropdown', 'value'),
     State('cluster-assignments-store', 'data'),
     State('ghidra-follow-request', 'data')],
    prevent_initial_call=True
)
def sync_ghidra_highlight(current, follow, view, dataset_id, cluster_assignments,
                          last_request):
    """
    Show the function open in Ghidra in Cluster Detail.

    - shown in the scatter: move the ring there (Patch on the last trace);
    - in the displayed cluster but filtered out: say so, don't touch filters;
    - in another cluster: select it in cluster-dropdown, which redraws the
      plot through update_filter_options -> apply_filters (drawing the ring),
      and ask view_cluster_details to refresh the statistics;
    - otherwise: clear the ring and explain in the status line.

    The view store is an Input so this always runs after a redraw (Dash then
    orders it after apply_filters / view_cluster_details), re-syncing the ring
    with what is on screen. Only a Ghidra move may switch cluster: a redraw
    the user caused (another cluster, filters) never pulls the view back.
    """
    ghidra_moved = any(t['prop_id'] in ('ghidra-current-store.data', 'ghidra-follow-switch.value')
                       for t in callback_context.triggered)

    def ring(point=None):
        # Only scatters built by create_binary_plot end with the overlay trace.
        if not view:
            return no_update
        patched = Patch()
        patched['data'][-1] = make_ghidra_overlay_trace(point).to_plotly_json()
        return patched

    if not follow:
        return ring(), _follow_status("Follow Ghidra is off"), no_update, no_update
    if not current:
        return no_update, _follow_status("Waiting for Ghidra…"), no_update, no_update

    processor = dataset_registry.get_processor(dataset_id)
    point, reason = _resolve_ghidra_function(processor, current)
    if point is None:
        level = "warning" if current.get('available') else "muted"
        return ring(), _follow_status(reason, level), no_update, no_update

    label = f"{point['name']} · {point['binary_name']}"
    same_dataset = bool(view) and view.get('dataset_id') == dataset_id
    if same_dataset and point['key'] in set(view.get('keys', [])):
        return (ring(point), _follow_status(f"In Ghidra: {label} (C{view['cluster']})", "success"),
                no_update, no_update)
    if same_dataset and point['binary_name'] in view.get('binaries', []):
        return (ring(), _follow_status(f"In Ghidra: {label} — hidden by the current filters",
                                       "warning"), no_update, no_update)

    target = _cluster_of(cluster_assignments, point['binary_name'])
    if target is None:
        return ring(), _follow_status(f"In Ghidra: {label} — no cluster yet", "warning"), \
            no_update, no_update
    if not ghidra_moved:
        return ring(), _follow_status(f"In Ghidra: {label} — in C{target}, not shown"), \
            no_update, no_update

    logger.info(f"Follow Ghidra: showing cluster C{target} for {label} ({point['offset']})")
    request = {'cluster': target, 'n': (last_request or {}).get('n', 0) + 1}
    return (no_update, _follow_status(f"In Ghidra: {label} → showing C{target}", "success"),
            target, request)


# ============================================================================
# Shutdown hook for Ghidra
# ============================================================================

@app.server.route('/_mapter/shutdown', methods=['POST'])
def shutdown_app():
    """Lets MapterBridge's "Stop MAPTER App" stop this app even when Ghidra did
    not start it (e.g. run by hand). Local requests only; the custom header
    cannot be sent by another web page without a CORS preflight, which this app
    never grants."""
    request = flask.request
    if request.remote_addr not in ('127.0.0.1', '::1') or \
            request.headers.get('X-MAPTER') != 'shutdown':
        flask.abort(403)
    logger.info("Shutdown requested by MapterBridge")
    # Exit after this reply is sent; also ends Flask's debug reloader parent.
    threading.Timer(0.3, os._exit, args=(0,)).start()
    return {'success': True, 'message': 'MAPTER app shutting down'}


# ============================================================================
# Run Application
# ============================================================================

if __name__ == '__main__':
    app.run(
        debug=config.DEBUG_MODE,
        host=config.SERVER_HOST,
        port=config.SERVER_PORT
    )
