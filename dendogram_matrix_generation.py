"""
Binary-to-binary similarity for MAPTER: per binary, the share of its functions
that have a function of the other binary within the radius δ on the map
(find_similar_groups), turned into a distance matrix for the dendrogram.
"""
import numpy as np
from scipy.spatial import cKDTree

from tqdm import tqdm

def rescale_matrix(matrix, transformation='log', power=0.5, modify_equals=False):
    """
    Rescale the values of a matrix to reduce disparity while keeping 0 and 1 values unchanged.

    Parameters:
    -----------
    matrix : array-like
        Input matrix with values typically between 0 and 1.
    transformation : str, optional (default='log')
        Type of transformation to apply:
        - 'log': applies log1p (natural log of 1 + x)
        - 'power': applies power transformation (x^power)
    power : float, optional (default=0.5)
        Exponent for power transformation. Only used if transformation='power'.

    Returns:
    --------
    np.ndarray
        Rescaled matrix with same shape as input. 0s and 1s are preserved.

    Raises:
    -------
    ValueError
        If an unsupported transformation is specified.
    """
    # Ensure input is a NumPy array of float type
    matrix = np.asarray(matrix, dtype=float)
    rescaled_matrix = matrix.copy()
    mask = (matrix != 0) & (matrix != 1)
    print(f"Rescaling {np.sum(mask)} values out of {matrix.size} total values.")
    if modify_equals:
        mask = (matrix == 0)
        matrix[mask] = 0.01
        np.fill_diagonal(matrix, 0)
    # Create mask for values that are neither 0 nor 1
    print(f"Rescaling {np.sum(mask)} values out of {matrix.size} total values.")
    mask = (matrix != 0) & (matrix != 1)

    if transformation == 'log':
        rescaled_matrix[mask] = np.log1p(matrix[mask])
    elif transformation == 'power':
        rescaled_matrix[mask] = np.power(matrix[mask], power)
    else:
        raise ValueError("Unsupported transformation type. Use 'log' or 'power'.")

    return rescaled_matrix

def obtain_percentage_close(percentage_close1: float, percentage_close2: float, 
                          metric: str = 'max') -> float:
    """
    Obtain the percentage of points that are close between two groups using various metrics.

    Parameters:
    percentage_close1 : float
        The percentage of points that are close in the first group.
    percentage_close2 : float
        The percentage of points that are close in the second group.
    metric : str, default 'max'
        The aggregation metric to use. Options: 'max', 'min', 'mean', 'harmonic_mean', 'geometric_mean'

    Returns:
    float
        The percentage of points that are close between the two groups based on the chosen metric.
    """    
    # Calculate based on metric
    if metric == 'max':
        result = max(percentage_close1, percentage_close2)
    elif metric == 'min':
        result = min(percentage_close1, percentage_close2)
    elif metric == 'mean':
        result = (percentage_close1 + percentage_close2) / 2
    else:
        raise ValueError(f"Unknown metric: {metric}. Choose from 'max', 'min', 'mean', 'harmonic_mean', 'geometric_mean'")
    
    # Ensure result is within valid range
    return min(result, 1.0)

def build_kd_tree_per_binary(df, binaries):
    """
    Build a KD-Tree for each binary in the DataFrame.
    Args:
        df : pandas DataFrame 
        binaries : list of binary names
    Returns:
        points_group : Dictionary with binary names as keys and their corresponding points as values.
        trees_group : Dictionary with binary names as keys and their corresponding KD-Trees as values.
        sizes_group : Dictionary with binary names as keys and the size of their corresponding points as values.
    """
    points_group = {}
    trees_group = {}
    sizes_group = {}

    for binary in binaries:
        if "embeddings" in df.columns:
            points = np.stack(df[df['binary_name'] == binary]["embeddings"].values)
        else:
            points = df[df['binary_name'] == binary][['x', 'y']].values
        points_group[binary] = points
        trees_group[binary] = cKDTree(points)
        sizes_group[binary] = len(points)
    return points_group, trees_group, sizes_group

################################################################################################################################################

def find_similar_groups(df, similarity_threshold=None, distance_threshold=1.0, reescale_matrix='log', metric_aggregation='mean', show_progress=False):
    """
    Find groups of binaries (of size 2 up to N) in the DataFrame that are similar based on spatial proximity.

    Parameters:
    df : pandas DataFrame
        DataFrame containing 'x', 'y', and 'binary_name' columns.
    similarity_threshold : float, optional
        The minimum percentage (between 0 and 1) of points that need to be close for groups to be considered similar.
    distance_threshold : float, optional
        The maximum distance between points to be considered as "close".
    reescale_matrix : str, optional
        The type of transformation to apply to the distance matrix ('log' or 'power').
    metric_aggregation : str, optional
        The aggregation metric to use. Options: 'max', 'min', 'mean', 'harmonic_mean', 'geometric_mean'.
    show_progress : bool, optional
        Whether to display a progress bar using tqdm.

    Returns:
    similar_groups : list of sets
        List containing sets of labels that are considered similar.
    """
    # Extract unique labels from the DataFrame
    binaries = df['binary_name'].unique()
    binaries_indices = {binaries: idx for idx, binaries in enumerate(binaries)}
    num_binaries = len(binaries)

    # Initialize an adjacency matrix to represent similarity between labels
    similarity_matrix = np.zeros((num_binaries, num_binaries), dtype=float)

    # Build KD-Trees for all groups
    points_group, trees_group, sizes_group = build_kd_tree_per_binary(df, binaries)

    # Compute similarity between all pairs of binaries
    iterator = range(num_binaries)
    if show_progress:
        iterator = tqdm(iterator, desc="Processing binaries", total=num_binaries)

    for i in iterator:
        for j in range(i, num_binaries):
            if i == j:
                similarity_matrix[i, j] = 1
                continue
            binary1 = binaries[i]
            binary2 = binaries[j]

            # Points of each group
            points1 = points_group[binary1]
            points2 = points_group[binary2]

            # For points in group1, find nearest in group2
            distances1, index_each_neighb1 = trees_group[binary2].query(points1, distance_upper_bound=distance_threshold)
            num_close_points1 = np.sum(distances1 != np.inf)  # amount of points that are closer than the distance threshold
            percentage_close1 = num_close_points1 / sizes_group[binary1]

            # For points in group2, find nearest in group1
            distances2, index_each_neighb2 = trees_group[binary1].query(points2, distance_upper_bound=distance_threshold)
            num_close_points2 = np.sum(distances2 != np.inf)
            percentage_close2 = num_close_points2 / sizes_group[binary2]

            # Check if both percentages exceed the similarity threshold
            # For two binaries to be considered similar, both must have at least the similarity threshold of points close to the other
            # otherwise, they could be sharing useless functions (points)
            idx1 = binaries_indices[binary1]
            idx2 = binaries_indices[binary2]
            if similarity_threshold:  # PRUNE SOME LEAFS TO SIMPLIFY THE MATRIX
                if percentage_close1 >= similarity_threshold and percentage_close2 >= similarity_threshold:
                    percentage_close = obtain_percentage_close(percentage_close1, percentage_close2, metric_aggregation)
                    similarity_matrix[idx1, idx2] = percentage_close
                    similarity_matrix[idx2, idx1] = percentage_close

            else:  # NO PRUNING, ALL BINARY PAIRS ARE CONSIDERED
                percentage_close = obtain_percentage_close(percentage_close1, percentage_close2, metric_aggregation)
                similarity_matrix[idx1, idx2] = percentage_close
                similarity_matrix[idx2, idx1] = percentage_close
    # Convert the similarity matrix to a distance matrix
    distance_matrix = 1 - similarity_matrix
    if reescale_matrix:
        distance_matrix = rescale_matrix(distance_matrix, transformation=reescale_matrix)
        # Fill NaN values with 0
        distance_matrix = np.nan_to_num(distance_matrix, nan=0.0)
    return distance_matrix

################################################################################################################################################


