import math
from collections import Counter


def cosine_distance(x, y):
    x_counts = Counter(x.split())
    y_counts = Counter(y.split())
    all_tokens = set(x_counts) | set(y_counts)
    if not all_tokens:
        return 0.0
    dot_product = sum(x_counts[token] * y_counts[token] for token in all_tokens)
    x_norm = math.sqrt(sum(value * value for value in x_counts.values()))
    y_norm = math.sqrt(sum(value * value for value in y_counts.values()))
    if x_norm == 0 or y_norm == 0:
        return 1.0
    return 1 - (dot_product / (x_norm * y_norm))


def jaccard_distance(x, y):
    x_tokens = set(x.split())
    y_tokens = set(y.split())
    union = x_tokens | y_tokens
    if not union:
        return 0.0
    intersection = x_tokens & y_tokens
    return 1 - (len(intersection) / len(union))


def distance(x, y, metric):
    if metric == "cosine":
        return cosine_distance(x, y)
    if metric == "jaccard":
        return jaccard_distance(x, y)
    raise ValueError("Invalid similarity metric.")


def minimum_distances(candidates, selected, metric):
    distances = []
    for candidate in candidates:
        min_candidate_distance = 1e10
        for selected_item in selected:
            min_candidate_distance = min(
                min_candidate_distance, distance(candidate, selected_item, metric)
            )
        distances.append(min_candidate_distance)
    return distances

