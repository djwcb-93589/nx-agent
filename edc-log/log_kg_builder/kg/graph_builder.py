from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

import pandas as pd

from .id_strategy import build_node_id, build_node_properties
from .normalization import merge_non_empty_properties, normalize_scalar
from .rules import RelationRule


@dataclass
class NodeRecord:
    label: str
    node_id: str
    properties: dict[str, Any]


@dataclass
class EdgeRecord:
    start_label: str
    start_id: str
    predicate: str
    end_label: str
    end_id: str
    properties: dict[str, Any]


@dataclass
class BuildResult:
    nodes: list[NodeRecord]
    edges: list[EdgeRecord]
    rule_hit_counter: Counter
    row_count: int

    @property
    def node_labels(self) -> set[str]:
        return {node.label for node in self.nodes}


class GraphBuilder:
    def __init__(self, rules: list[RelationRule]) -> None:
        self.rules = rules

    def build(self, df: pd.DataFrame) -> BuildResult:
        node_index: dict[tuple[str, str], NodeRecord] = {}
        edge_index: dict[tuple[str, str, str, str, str], EdgeRecord] = {}
        rule_hits: Counter = Counter()

        for row in df.to_dict(orient="records"):
            for rule in self.rules:
                if not rule.matches(row):
                    continue

                subject_id = build_node_id(rule.subject_type, rule.subject_id_source, row)
                object_id = build_node_id(rule.object_type, rule.object_id_source, row)
                if subject_id is None or object_id is None:
                    continue

                self._upsert_node(
                    node_index,
                    label=rule.subject_type,
                    node_id=subject_id,
                    id_source=rule.subject_id_source,
                    row=row,
                )
                self._upsert_node(
                    node_index,
                    label=rule.object_type,
                    node_id=object_id,
                    id_source=rule.object_id_source,
                    row=row,
                )

                edge_props = self._build_edge_properties(rule, row)
                self._upsert_edge(
                    edge_index,
                    start_label=rule.subject_type,
                    start_id=subject_id,
                    predicate=rule.predicate,
                    end_label=rule.object_type,
                    end_id=object_id,
                    edge_props=edge_props,
                )
                rule_hits[rule.rule_id] += 1

        return BuildResult(
            nodes=list(node_index.values()),
            edges=list(edge_index.values()),
            rule_hit_counter=rule_hits,
            row_count=len(df),
        )

    def _upsert_node(
        self,
        node_index: dict[tuple[str, str], NodeRecord],
        *,
        label: str,
        node_id: str,
        id_source: str,
        row: dict[str, Any],
    ) -> None:
        key = (label, node_id)
        props = build_node_properties(label, node_id, id_source, row)
        existing = node_index.get(key)
        if existing is None:
            node_index[key] = NodeRecord(label=label, node_id=node_id, properties=dict(props))
            return

        merge_non_empty_properties(existing.properties, props)

    def _upsert_edge(
        self,
        edge_index: dict[tuple[str, str, str, str, str], EdgeRecord],
        *,
        start_label: str,
        start_id: str,
        predicate: str,
        end_label: str,
        end_id: str,
        edge_props: dict[str, Any],
    ) -> None:
        key = (start_label, start_id, predicate, end_label, end_id)
        existing = edge_index.get(key)
        if existing is None:
            edge_index[key] = EdgeRecord(
                start_label=start_label,
                start_id=start_id,
                predicate=predicate,
                end_label=end_label,
                end_id=end_id,
                properties=dict(edge_props),
            )
            return

        merge_non_empty_properties(existing.properties, edge_props)

    def _build_edge_properties(
        self,
        rule: RelationRule,
        row: dict[str, Any],
    ) -> dict[str, Any]:
        edge_props: dict[str, Any] = {}
        for field in rule.edge_property_fields:
            value = normalize_scalar(row.get(field))
            if value is not None:
                edge_props[field] = value
        return edge_props
