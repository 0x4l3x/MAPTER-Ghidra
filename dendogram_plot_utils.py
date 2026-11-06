"""
AVClass annotations for the MAPTER dendrogram: which clusters get a family tag
(get_cluster_avclass_info_enhanced) and the tag colours (get_tag_color).
"""
from collections import Counter

# SIMPLE DENDO PLOT


################################################################################################################################################

# #### dendrograms with avclass tags (plot_dendrogram_with_avclass_enhanced)


################################################################################################################################################


###########################################################################################################################################################################


####################################################################################################################################################################################


################################################################################################################################################


################################################################################################################################################


################################################################################################################################################
# UTILITY FUNCTIONS FOR ENHANCED DENDROGRAMS WITH AVCLASS TAGS
################################################################################################################################################


def get_binary_names_from_cluster_node(merge_idx, dendro, labels, linkage_matrix, n_samples):
    """
    Get all binary names that belong to a specific cluster node in the dendrogram.

    Args:
        merge_idx: Index of the merge in the dendrogram (0-based)
        dendro: Dendrogram dictionary returned by sch.dendrogram()
        labels: Original labels list
        linkage_matrix: Linkage matrix from clustering
        n_samples: Number of original samples

    Returns:
        List of binary names in this cluster
    """
    def get_leaves_from_cluster(cluster_idx):
        """Recursively get all leaf indices from a cluster."""
        if cluster_idx < n_samples:
            # Leaf node - return the original sample index
            return [cluster_idx]
        else:
            # Internal node
            merge_idx_internal = cluster_idx - n_samples
            if merge_idx_internal < len(linkage_matrix):
                left_cluster = int(linkage_matrix[merge_idx_internal][0])
                right_cluster = int(linkage_matrix[merge_idx_internal][1])

                left_leaves = get_leaves_from_cluster(left_cluster)
                right_leaves = get_leaves_from_cluster(right_cluster)

                return left_leaves + right_leaves
            else:
                return []

    # Get the cluster index for this merge
    cluster_idx = n_samples + merge_idx

    # Get all leaf indices in this cluster
    leaf_indices = get_leaves_from_cluster(cluster_idx)

    # Map leaf indices to binary names using dendrogram's leaves mapping
    dendro_leaves = dendro['leaves']
    binary_names = []

    for leaf_idx in leaf_indices:
        # Find where this leaf appears in the dendrogram's leaf order
        try:
            dendro_position = dendro_leaves.index(leaf_idx)
            # Get the corresponding label from ivl (visual labels)
            binary_name = dendro['ivl'][dendro_position]
            binary_names.append(binary_name)
        except ValueError:
            # Fallback to original label if not found in dendro leaves
            if leaf_idx < len(labels):
                binary_names.append(labels[leaf_idx])

    return binary_names

def get_cluster_avclass_info_enhanced(linkage_matrix, labels, avclass_tags, dendro):
    """
    Enhanced version that uses dendrogram structure to map cluster information.

    Args:
        linkage_matrix: The linkage matrix from hierarchical clustering
        labels: List of original labels
        avclass_tags: Dictionary mapping labels to avclass tags
        dendro: Dendrogram dictionary from sch.dendrogram()

    Returns:
        Tuple of (cluster_list, cluster_info) matching Plotly format
    """
    n_samples = len(labels)
    cluster_info = {}

    # Initialize leaf nodes with their avclass tags
    for i, label in enumerate(labels):
        if label in avclass_tags:
            cluster_info[i] = (avclass_tags[label], 100.0, {avclass_tags[label]: 1}, [label], 0.0)
        else:
            cluster_info[i] = ("Unknown", 100.0, {"Unknown": 1}, [label], 0.0)

    # Process internal nodes using dendrogram structure
    for merge_idx in range(len(linkage_matrix)):
        cluster_idx = n_samples + merge_idx
        distance = linkage_matrix[merge_idx][2]  # Get distance from linkage matrix

        # Get binary names for this cluster node
        binary_names = get_binary_names_from_cluster_node(merge_idx, dendro, labels, linkage_matrix, n_samples)

        # Get avclass tags for these binary names
        all_tags = []
        for binary_name in binary_names:
            if binary_name in avclass_tags:
                all_tags.append(avclass_tags[binary_name])
            else:
                all_tags.append("Unknown")

        # Calculate statistics
        if all_tags:
            tag_counts = Counter(all_tags)
            most_common_tags = tag_counts.most_common()
            max_count = most_common_tags[0][1]
            # Get all tags with the maximum count
            tied_tags = [tag for tag, count in most_common_tags if count == max_count]
            # Sort alphabetically and pick the first one
            most_common_tag = sorted(tied_tags)[0]
            percentage = (max_count / len(all_tags)) * 100
            cluster_info[cluster_idx] = (most_common_tag, percentage, dict(tag_counts), binary_names, distance)
        else:
            cluster_info[cluster_idx] = ("Unknown", 0.0, {}, binary_names, distance)

    # Convert to list and sort by distance (ascending order - closest first)
    cluster_list = [(node_idx, info[0], info[1], info[2], info[3], info[4]) 
                   for node_idx, info in cluster_info.items()]
    cluster_list.sort(key=lambda x: x[5])  # Sort by distance (index 5)

    return cluster_list, cluster_info


#############################################################################################
# Some fix for enabling the avclass info in the dendrogram
############################################################################################


################################################################################################################################################


def get_tag_color(tag, color_map):
    """Get consistent color for each tag type using a curated pastel color palette."""
    if tag not in color_map:
        # Use pastel colors for better visual appeal and less strain
        colors = [
            '#FFB3BA',  # Light pink - for high-threat malware
            '#BFEFFF',  # Light sky blue - for backdoors/RATs
            '#BFFFBF',  # Light green - for utilities/tools
            '#E6CCFF',  # Light purple - for evasion techniques
            '#FFD4B3',  # Light orange - for persistence mechanisms
            '#FFFFCC',  # Light yellow - for unknown/unclassified
            '#D2B48C',  # Light brown - for system tools
            '#F8C8DC',  # Light pink - for lateral movement
            '#D3D3D3',  # Light gray - for benign/legitimate
            '#B3E5D1',  # Light teal - for network tools
            '#FFDAB9',  # Peach puff - for collection
            '#C8D6F0',  # Light blue - for discovery
            '#F0C8E0',  # Light pink - for command & control
            '#D9F7BE',  # Light green - for exfiltration
            '#FFF2CC',  # Light gold - for impact
            '#F0E6D2',  # Light beige - for defense evasion
            '#E8E8E8',  # Very light gray - for analysis tools
            '#C7EDDE',  # Pale teal - for reconnaissance
            '#E0D4F7',  # Light lavender - for privilege escalation
            '#FFD0C4'   # Light salmon - for initial access
        ]
        color_map[tag] = colors[len(color_map) % len(colors)]
    return color_map[tag]


