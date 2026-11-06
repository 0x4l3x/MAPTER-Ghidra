"""
Visualization Components for Malware Binary Clustering Dashboard
=================================================================
Provides dendrogram and scatter plot visualizations using Plotly.
"""

import logging
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.figure_factory as ff
from typing import Dict, List, Optional
from scipy.cluster.hierarchy import linkage, dendrogram as sch_dendrogram
from scipy.spatial.distance import squareform

logger = logging.getLogger(__name__)

try:
    from dendogram_plot_utils import (
        get_cluster_avclass_info_enhanced,
        get_tag_color
    )
except ImportError as e:
    logger.warning(f"Could not import plot utilities: {e}")


class DendrogramVisualizer:
    """
    Creates interactive dendrogram visualizations using Plotly.
    """
    
    def __init__(self):
        self.color_map = {}
    
    def create_dendrogram(
        self,
        dist_matrix: np.ndarray,
        labels: List[str],
        avclass_tags: Optional[Dict[str, str]] = None,
        title: str = "Binary Clustering Dendrogram",
        height: int = 480,
        width: Optional[int] = None,
        orientation: str = 'bottom',
        cut_threshold: float = 0.75,
        avclass_threshold: float = 0.9,
        cluster_groups: Optional[List[Dict]] = None
    ) -> go.Figure:
        """
        Create an interactive Plotly dendrogram.

        Args:
            dist_matrix: Distance matrix
            labels: Binary labels
            avclass_tags: Dictionary mapping labels to tags
            title: Plot title
            height: Figure height in pixels
            width: Figure width in pixels; if None, scales with #binaries
            orientation: Dendrogram orientation ('bottom', 'left', 'right', 'top')
            cut_threshold: Distance threshold shown as the cut line; clusters
                merging below it are colored (illustrates cluster granularity)
            avclass_threshold: Distance below which clusters get an avclass tag
                annotation (independent of, and usually higher than, the cut)

        Returns:
            Plotly Figure object
        """
        try:
            # Compute linkage
            condensed = squareform(dist_matrix)
            Z = linkage(condensed, method='average')

            # Create dendrogram using Plotly; color clusters below the cut.
            fig = ff.create_dendrogram(
                dist_matrix,
                labels=labels,
                orientation=orientation,
                distfun=lambda x: squareform(x),
                linkagefun=lambda x: linkage(x, 'average'),
                color_threshold=cut_threshold
            )

            # Get dendrogram structure for annotations
            dendro_dict = sch_dendrogram(
                Z,
                labels=labels,
                orientation=orientation,
                no_plot=True
            )

            # Add AVClass annotations if provided
            if avclass_tags:
                self._add_avclass_annotations(
                    fig,
                    Z,
                    labels,
                    avclass_tags,
                    dendro_dict,
                    orientation,
                    avclass_threshold
                )
            
            # Update layout
            fig.update_layout(
                title=dict(
                    text=title,
                    font=dict(size=16, family='Arial'),
                    x=0.5,
                    xanchor='center'
                ),
                xaxis=dict(
                    title="Binaries",
                    tickangle=45 if orientation in ['bottom', 'top'] else 0,
                    tickfont=dict(size=9)
                ),
                yaxis=dict(
                    title="Distance",
                    tickfont=dict(size=11)
                ),
                height=height,
                autosize=True,
                margin=dict(l=50, r=20, t=50, b=90),
                showlegend=False,
                hovermode='closest',
                plot_bgcolor='white',
                paper_bgcolor='white'
            )

            # Add gridlines
            fig.update_xaxes(showgrid=True, gridwidth=0.5, gridcolor='lightgray')
            fig.update_yaxes(showgrid=True, gridwidth=0.5, gridcolor='lightgray')

            # Draw the distance-threshold cut line (illustrates cluster granularity)
            if orientation in ['bottom', 'top']:
                fig.add_hline(
                    y=cut_threshold, line_dash='dash', line_color='#d62728',
                    line_width=1.5,
                    annotation_text=f"cut = {cut_threshold:.2f}",
                    annotation_position='top left',
                    annotation_font=dict(color='#d62728', size=11)
                )
            else:
                fig.add_vline(
                    x=cut_threshold, line_dash='dash', line_color='#d62728',
                    line_width=1.5,
                    annotation_text=f"cut = {cut_threshold:.2f}",
                    annotation_position='top right',
                    annotation_font=dict(color='#d62728', size=11)
                )

            # Left-to-right cluster-number labels at the cut line, so dropdown
            # "Cluster N" maps to the N-th group from the left.
            if cluster_groups and orientation in ['bottom', 'top']:
                leaf_index = {lab: i for i, lab in enumerate(dendro_dict['ivl'])}
                for grp in cluster_groups:
                    number = grp.get('number')
                    bins = grp.get('binaries', [])
                    idxs = [leaf_index[b] for b in bins if b in leaf_index]
                    if not idxs:
                        continue
                    center_x = 10 * (sum(idxs) / len(idxs)) + 5
                    fig.add_annotation(
                        x=center_x, y=cut_threshold,
                        text=f"C{number}",
                        showarrow=False,
                        yshift=12,
                        font=dict(size=10, color='#2c3e50', family='Arial Black'),
                        bgcolor='rgba(255,255,255,0.75)',
                        bordercolor='#2c3e50', borderwidth=1, borderpad=2,
                    )

            return fig
            
        except Exception as e:
            logger.error(f"Error creating dendrogram: {e}")
            # Return empty figure with error message
            fig = go.Figure()
            fig.add_annotation(
                text=f"Error creating dendrogram: {str(e)}",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16, color='red')
            )
            fig.update_layout(height=height, width=width)
            return fig
    
    def _add_avclass_annotations(
        self,
        fig: go.Figure,
        linkage_matrix: np.ndarray,
        labels: List[str],
        avclass_tags: Dict[str, str],
        dendro_dict: dict,
        orientation: str,
        threshold: float
    ):
        """
        Add AVClass tag annotations to dendrogram.
        
        Args:
            fig: Plotly figure
            linkage_matrix: Linkage matrix
            labels: Binary labels
            avclass_tags: Tag mappings
            dendro_dict: Dendrogram dictionary from scipy
            orientation: Dendrogram orientation
            threshold: Distance threshold for annotations
        """
        try:
            # Get cluster information
            cluster_list, cluster_info = get_cluster_avclass_info_enhanced(
                linkage_matrix, labels, avclass_tags, dendro_dict
            )
            
            # Extract coordinates from dendrogram
            icoord = np.array(dendro_dict['icoord'])
            dcoord = np.array(dendro_dict['dcoord'])
            
            # Add annotations for significant clusters
            annotations = []
            for i in range(len(icoord)):
                # Calculate position
                if orientation in ['bottom', 'top']:
                    x_pos = (icoord[i][1] + icoord[i][2]) / 2
                    y_pos = dcoord[i][1]
                else:  # left or right
                    x_pos = dcoord[i][1]
                    y_pos = (icoord[i][1] + icoord[i][2]) / 2
                
                # Only annotate clusters below threshold
                if y_pos > threshold:
                    continue
                
                # Find matching cluster
                matching_clusters = [
                    c for c in cluster_list 
                    if abs(c[5] - y_pos) < 0.001  # distance match
                ]
                
                if not matching_clusters:
                    continue
                
                cluster = matching_clusters[0]
                _, tag, percentage, _, binary_names, distance = cluster
                
                if percentage >= 100.0:  # Skip pure clusters
                    continue
                
                # Get color
                tag_color = get_tag_color(tag, self.color_map)
                
                # Create annotation text
                annotation_text = f"{tag}<br>{percentage:.1f}%"
                
                # Add annotation
                annotation = dict(
                    x=x_pos,
                    y=y_pos,
                    text=annotation_text,
                    showarrow=True,
                    arrowhead=2,
                    arrowsize=1,
                    arrowwidth=1,
                    arrowcolor='black',
                    ax=20,
                    ay=-30,
                    bgcolor=tag_color,
                    opacity=0.8,
                    bordercolor='black',
                    borderwidth=1,
                    borderpad=4,
                    font=dict(size=10, color='black', family='Arial Black')
                )
                annotations.append(annotation)
            
            fig.update_layout(annotations=annotations)
            
        except Exception as e:
            logger.error(f"Error adding annotations: {e}")


# Name of the overlay trace marking the function under Ghidra's cursor. It is
# always the LAST trace of a cluster scatter, so app.py can move it with
# Patch()['data'][-1] without resending the figure.
GHIDRA_OVERLAY_NAME = "__ghidra_current__"


def make_ghidra_overlay_trace(point: Optional[Dict] = None) -> go.Scatter:
    """
    Ring marker for the function currently open in Ghidra.

    The ring ignores hover/click (hoverinfo='skip') so the real point under it
    keeps its tooltip and click-to-navigate customdata.

    Args:
        point: dict with 'x' and 'y', or None for an empty overlay.
    """
    x, y = ([], []) if point is None else ([point['x']], [point['y']])
    return go.Scatter(
        x=x, y=y, mode='markers', name=GHIDRA_OVERLAY_NAME,
        marker=dict(symbol='circle-open', size=22, color='crimson',
                    line=dict(width=3, color='crimson')),
        hoverinfo='skip', showlegend=False,
    )


class BinaryPlotVisualizer:
    """
    Creates interactive scatter plots for binary function visualization.
    """

    def create_binary_plot(
        self,
        data: pd.DataFrame,
        binary_names: Optional[List[str]] = None,
        color_by: str = "binary_name",
        size_column: Optional[str] = "size",
        title: str = "Binary Functions Visualization",
        height: int = 600,
        width: Optional[int] = None,
        highlight: Optional[Dict] = None,
        uirevision: Optional[str] = None
    ) -> go.Figure:
        """
        Create interactive scatter plot of binary functions.

        Args:
            data: DataFrame with function data
            binary_names: Specific binaries to plot
            color_by: Column to color points by
            size_column: Column to use for point sizing
            title: Plot title
            height: Figure height
            width: Figure width
            highlight: Point to ring as "open in Ghidra" (see
                make_ghidra_overlay_trace); the overlay trace is appended last
                whenever the plot has data, even if this is None
            uirevision: Plotly uirevision; keep it constant for the same view
                so zoom/pan survive filter changes and overlay updates

        Returns:
            Plotly Figure object
        """
        if data is None or len(data) == 0:
            fig = go.Figure()
            fig.add_annotation(
                text="No data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=20)
            )
            fig.update_layout(height=height, width=width, uirevision=uirevision)
            # Keep the (empty) overlay so a fully filtered-out view still counts
            # as showing its cluster ("hidden by filters", not "switch cluster").
            fig.add_trace(make_ghidra_overlay_trace())
            return fig
        
        plot_df = data.copy()
        
        # Filter by binary names if specified
        if binary_names:
            plot_df = plot_df[plot_df['binary_name'].isin(binary_names)]
        
        # Ensure required columns exist
        if 'x' not in plot_df.columns or 'y' not in plot_df.columns:
            fig = go.Figure()
            fig.add_annotation(
                text="Missing x/y coordinates in data",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16, color='red')
            )
            fig.update_layout(height=height, width=width)
            return fig
        
        # Resolve the column to color by (fall back to binary_name).
        if not color_by or color_by not in plot_df.columns:
            color_by = 'binary_name'

        palette = [
            '#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
            '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf',
            '#393b79', '#637939', '#8c6d31', '#843c39', '#7b4173',
        ]

        def _customdata(sub):
            # [address, function_name, binary_name] — preserved for Ghidra nav.
            cd = []
            for _, row in sub.iterrows():
                addr = row.get('offset', row.get('address', None))
                if isinstance(addr, (int, np.int64)):
                    addr = f"0x{addr:x}"
                elif addr and not str(addr).startswith('0x'):
                    addr = f"0x{addr}"
                cd.append([addr, row.get('name', row.get('function_name', None)),
                           row.get('binary_name')])
            return cd

        def _hover(sub):
            texts = []
            for _, row in sub.iterrows():
                parts = [f"<b>{row.get('binary_name', '')}</b>",
                         f"Position: ({row['x']:.3f}, {row['y']:.3f})"]
                if 'offset' in row and pd.notna(row['offset']):
                    parts.append(f"Offset: {row['offset']}")
                if 'name' in row and pd.notna(row['name']):
                    parts.append(f"Function: {row['name']}")
                if 'size' in row and pd.notna(row['size']):
                    parts.append(f"Size: {row['size']}")
                if 'rule_name' in row and pd.notna(row['rule_name']):
                    rule_text = str(row['rule_name']).replace("; ", ";<br>&nbsp;&nbsp;&nbsp;&nbsp;")
                    parts.append(f"Rule(s): {rule_text}")
                if color_by not in ('binary_name', 'name', 'size', 'offset', 'rule_name') \
                        and color_by in row and pd.notna(row[color_by]):
                    parts.append(f"{color_by}: {row[color_by]}")
                texts.append("<br>".join(parts))
            return texts

        try:
            fig = go.Figure()
            is_numeric = (
                pd.api.types.is_numeric_dtype(plot_df[color_by])
                and not pd.api.types.is_bool_dtype(plot_df[color_by])
                and color_by != 'binary_name'
            )

            if is_numeric:
                # Continuous colour scale (e.g. function size).
                fig.add_trace(go.Scatter(
                    x=plot_df['x'], y=plot_df['y'], mode='markers',
                    marker=dict(color=plot_df[color_by], colorscale='Viridis',
                                showscale=True, colorbar=dict(title=color_by),
                                opacity=0.75, line=dict(width=0.5, color='white')),
                    text=_hover(plot_df),
                    hovertemplate='%{text}<extra></extra>',
                    customdata=_customdata(plot_df),
                    showlegend=False,
                ))
            else:
                cats = plot_df[color_by].fillna('(none)').astype(str)
                unique_cats = list(dict.fromkeys(cats))  # unique, order-preserving
                if len(unique_cats) <= 60:
                    # One trace per category → interactive legend.
                    for idx, cat in enumerate(unique_cats):
                        sub = plot_df[cats.values == cat]
                        name = cat[:16] + '…' if len(cat) > 16 else cat
                        fig.add_trace(go.Scatter(
                            x=sub['x'], y=sub['y'], mode='markers', name=name,
                            marker=dict(color=palette[idx % len(palette)],
                                        opacity=0.75, line=dict(width=0.5, color='white')),
                            text=_hover(sub),
                            hovertemplate='%{text}<extra></extra>',
                            customdata=_customdata(sub),
                        ))
                else:
                    # Too many categories for a legend: single colour-coded trace.
                    code = {c: i for i, c in enumerate(unique_cats)}
                    fig.add_trace(go.Scatter(
                        x=plot_df['x'], y=plot_df['y'], mode='markers',
                        marker=dict(color=[palette[code[c] % len(palette)] for c in cats],
                                    opacity=0.75, line=dict(width=0.5, color='white')),
                        text=_hover(plot_df),
                        hovertemplate='%{text}<extra></extra>',
                        customdata=_customdata(plot_df),
                        showlegend=False,
                    ))

            fig.update_layout(
                title=dict(text=title, font=dict(size=16, family='Arial'),
                           x=0.5, xanchor='center'),
                xaxis=dict(title="Dimension 1 (x)", showgrid=True,
                           gridwidth=0.5, gridcolor='lightgray'),
                yaxis=dict(title="Dimension 2 (y)", showgrid=True,
                           gridwidth=0.5, gridcolor='lightgray'),
                height=height,
                autosize=True,
                margin=dict(l=50, r=20, t=50, b=50),
                hovermode='closest',
                plot_bgcolor='white',
                paper_bgcolor='white',
                legend=dict(title=color_by, orientation="v", yanchor="top", y=1,
                            xanchor="left", x=1.02),
                uirevision=uirevision,
            )

            # Must stay the last trace (see GHIDRA_OVERLAY_NAME).
            fig.add_trace(make_ghidra_overlay_trace(highlight))
            return fig
            
        except Exception as e:
            logger.error(f"Error creating scatter plot: {e}")
            fig = go.Figure()
            fig.add_annotation(
                text=f"Error: {str(e)}",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16, color='red')
            )
            fig.update_layout(height=height, width=width)
            return fig
    


