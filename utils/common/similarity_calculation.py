
import numpy as np


def cos_dist(vec1, vec2):
    """
    Get the cosine similarity of two vectors
    """
    dist = float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2)))
    return dist