from datetime import datetime
import hashlib

from agent import compat

compat.ensure_parser_path()

import evaluator
import grouping


def default_raw_grouping_setting():
    return evaluator.default_raw_grouping_setting()


def build_deep_group_tree(logs, setting):
    parser = grouping.LogParser(
        rex=setting["regex"],
        depth=setting.get("depth", 4),
        st=setting.get("st", 0.5),
    )
    start_time = datetime.now()
    root_node = grouping.Node()
    log_clusters = []

    parser.load_data(logs)
    for _, line in parser.df_log.iterrows():
        log_id = line["LineId"]
        log_tokens = parser.preprocess(line["Content"]).strip().split()
        match_cluster = parser.treeSearch(root_node, log_tokens)

        if match_cluster is None:
            new_cluster = grouping.Logcluster(logTemplate=log_tokens, logIDL=[log_id])
            log_clusters.append(new_cluster)
            parser.addSeqToPrefixTree(root_node, new_cluster)
        else:
            new_template = parser.getTemplate(log_tokens, match_cluster.logTemplate)
            match_cluster.logIDL.append(log_id)
            if " ".join(new_template) != " ".join(match_cluster.logTemplate):
                match_cluster.logTemplate = new_template

    grouped_logs = parser.outputResult(log_clusters)
    parser.total_time += (datetime.now() - start_time).total_seconds()
    groups_dict = evaluator.group_logs_using_parser(grouped_logs)
    groups_dict = evaluator.sort_dict_by_content_length(groups_dict)
    tree = _serialize_tree(root_node)
    tree["clusters"] = [_serialize_cluster(cluster) for cluster in log_clusters]
    tree["group_count"] = len(groups_dict)
    tree["line_count"] = len(logs)
    return parser, groups_dict, tree


def get_logs_from_group(group_records):
    return evaluator.get_logs_from_group(group_records)


def _serialize_tree(root_node):
    return {
        "depth": root_node.depth,
        "token": root_node.digitOrtoken,
        "children": _serialize_children(root_node.childD),
    }


def _serialize_children(children):
    if isinstance(children, list):
        return [
            {
                "edge": "cluster",
                "cluster": _serialize_cluster(cluster),
            }
            for cluster in children
        ]

    serialized = []
    for edge, child in children.items():
        serialized.append(
            {
                "edge": str(edge),
                "depth": child.depth,
                "token": child.digitOrtoken,
                "children": _serialize_children(child.childD),
            }
        )
    return serialized


def _serialize_cluster(cluster):
    template = " ".join(cluster.logTemplate)
    return {
        "event_id": hashlib.md5(template.encode("utf-8")).hexdigest()[0:8],
        "event_template": template,
        "line_ids": list(cluster.logIDL),
        "count": len(cluster.logIDL),
    }

