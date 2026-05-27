import random

from agent.tools import similarity_tools


def logs_from_group(group_records):
    return [record["Content"] for record in group_records]


def select_representative_logs(
    logs,
    sample_size,
    metric="jaccard",
    max_logs=200,
    nearest=False,
    records=False,
):
    if records:
        logs = logs_from_group(logs)
    logs = list(logs)

    if max_logs is not None and len(logs) > max_logs:
        logs = random.sample(logs, max_logs)

    if len(logs) < sample_size:
        sample_size = len(logs)

    if sample_size <= 0:
        return []

    if metric == "random":
        return [item.replace(",", "") for item in random.sample(logs, sample_size)]

    sample_list = []
    selected = []
    for _ in range(sample_size):
        if not sample_list:
            index = max(range(len(logs)), key=lambda idx: len(logs[idx].split()))
            selected.append(logs[index])
            sample_list.append(logs[index])
            del logs[index]
            continue

        candidate_distances = similarity_tools.minimum_distances(logs, selected, metric)
        if nearest:
            best_candidate = min(
                range(len(candidate_distances)), key=lambda idx: candidate_distances[idx]
            )
        else:
            best_candidate = max(
                range(len(candidate_distances)), key=lambda idx: candidate_distances[idx]
            )

        selected.append(logs[best_candidate])
        sample_list.append(logs[best_candidate])
        logs.remove(logs[best_candidate])

    return [item.replace(",", "") for item in sample_list]

