"""
Data Processing Module for Malware Binary Clustering
=====================================================
Handles data loading, distance matrix generation, and cluster extraction.
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional
from scipy.cluster.hierarchy import linkage, fcluster, dendrogram
from scipy.spatial.distance import squareform

logger = logging.getLogger(__name__)


from dendogram_matrix_generation import find_similar_groups

class DataProcessor:
    """
    Handles all data processing operations for the malware clustering dashboard.
    """
    
    def __init__(self):
        self.data = None
        self.dist_matrix = None
        self.labels = None
        self.avclass_tags = None

    def load_data(self) -> Optional[pd.DataFrame]:
        """Load the per-function data into ``self.data`` (and ``self.avclass_tags``).
        Implemented by dataset_registry.ManifestDataProcessor."""
        raise NotImplementedError

    def generate_distance_matrix(
        self, 
        data: Optional[pd.DataFrame] = None,
        function_threshold: float = 5.0,
        binary_threshold: float = 0.2,
        reescale_method: Optional[str] = None
    ) -> np.ndarray:
        """
        Generate distance matrix from embedding data.
        
        Args:
            data: DataFrame with embeddings (uses self.data if None)
            function_threshold: Threshold for function similarity
            binary_threshold: Threshold for binary similarity
            reescale_method: Method to rescale matrix ('log', 'power', or None)
            
        Returns:
            Distance matrix as numpy array
        """
        if data is None:
            data = self.data
        
        if data is None:
            raise ValueError("No data available. Call load_data() first.")
        
        try:
            # Generate distance matrix using existing function
            self.dist_matrix = find_similar_groups(
                data,
                similarity_threshold=binary_threshold,
                distance_threshold=function_threshold,
                reescale_matrix=reescale_method
            )
            
            # Store labels
            self.labels = data['binary_name'].unique().tolist()
            
            logger.info(f"Generated {self.dist_matrix.shape} distance matrix")
            return self.dist_matrix
            
        except Exception as e:
            logger.error(f"Error generating distance matrix: {e}")
            # Return identity matrix as fallback
            n = len(data['binary_name'].unique())
            return np.eye(n)
    
    def get_binary_labels(self) -> List[str]:
        """
        Get list of binary labels.
        
        Returns:
            List of binary names
        """
        if self.labels is not None:
            return self.labels
        
        if self.data is not None:
            self.labels = self.data['binary_name'].unique().tolist()
            return self.labels
        
        return []
    
    def get_avclass_tags(self) -> Dict[str, str]:
        """
        Get AVClass tag mappings.
        
        Returns:
            Dictionary mapping binary names to AVClass tags
        """
        return self.avclass_tags or {}
    

    def get_ordered_clusters(
        self,
        dist_matrix: np.ndarray,
        threshold: float,
        labels: List[str]
    ) -> List[Dict]:
        """
        Get clusters at a threshold, numbered left-to-right by dendrogram order.

        Clusters obtained by cutting a dendrogram are contiguous in the leaf
        order, so numbering by each cluster's leftmost leaf makes cluster N the
        N-th group from the left on the dendrogram. This single source of truth
        keeps the dropdown numbering and the on-dendrogram labels consistent.

        Returns:
            Ordered list (left-to-right) of dicts:
            {'number': int, 'binaries': [names sorted left-to-right]}
        """
        try:
            condensed = squareform(dist_matrix)
            Z = linkage(condensed, method='average')
            cluster_ids = fcluster(Z, threshold, criterion='distance')

            # Left-to-right leaf order (labels as laid out on the dendrogram).
            leaf_order = dendrogram(Z, labels=list(labels), no_plot=True)['ivl']
            position = {label: i for i, label in enumerate(leaf_order)}

            groups: Dict[int, List[str]] = {}
            for label, cluster_id in zip(labels, cluster_ids):
                groups.setdefault(int(cluster_id), []).append(label)

            ordered = sorted(
                groups.values(),
                key=lambda bins: min(position.get(b, 0) for b in bins)
            )

            result = []
            for i, bins in enumerate(ordered, start=1):
                bins_sorted = sorted(bins, key=lambda b: position.get(b, 0))
                result.append({'number': i, 'binaries': bins_sorted})
            return result

        except Exception as e:
            logger.error(f"Error ordering clusters: {e}")
            return []

    def get_cluster_data(self, binary_names: List[str]) -> pd.DataFrame:
        """
        Get data for specific binaries.
        
        Args:
            binary_names: List of binary names to filter
            
        Returns:
            DataFrame with data for specified binaries
        """
        if self.data is None:
            return pd.DataFrame()
        
        return self.data[self.data['binary_name'].isin(binary_names)].copy()
    
    
    def get_binary_statistics(self, binary_names: List[str]) -> Dict[str, Dict]:
        """
        Get detailed statistics for specific binaries.
        
        Args:
            binary_names: List of binary names to get statistics for
            
        Returns:
            Dictionary mapping binary names to their statistics
        """
        if self.data is None:
            return {}
        
        stats = {}
        for binary_name in binary_names:
            binary_df = self.data[self.data['binary_name'] == binary_name]
            
            if len(binary_df) == 0:
                continue
            
            # Calculate statistics
            total_functions = len(binary_df)
            
            # File size - try different column names
            file_size = None
            for col in ['file_size', 'binary_size', 'size']:
                if col in binary_df.columns:
                    # Get the max or first value (assuming same for all functions in a binary)
                    file_size = binary_df[col].max()
                    break
            
            # CAPA functions count
            capa_count = 0
            if 'rule_name' in binary_df.columns:
                capa_count = binary_df['rule_name'].notna().sum()
            
            # Library functions count
            lib_count = 0
            if 'library_name' in binary_df.columns:
                lib_count = binary_df['library_name'].notna().sum()
            
            # AVClass tag
            avclass_tag = self.avclass_tags.get(binary_name, 'Unknown') if self.avclass_tags else 'N/A'
            
            stats[binary_name] = {
                'file_size': file_size,
                'total_functions': total_functions,
                'capa_functions': capa_count,
                'library_functions': lib_count,
                'avclass_tag': avclass_tag
            }
        
        return stats
    


