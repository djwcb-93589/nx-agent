from __future__ import annotations

from datetime import date, datetime, time
from typing import Any

from neo4j.graph import Node, Path, Relationship


def serialize_neo4j_value(value: Any) -> Any:
    if isinstance(value, Node):
        return {
            "type": "node",
            "labels": list(value.labels),
            "element_id": value.element_id,
            "properties": dict(value.items()),
        }
    if isinstance(value, Relationship):
        return {
            "type": "relationship",
            "relationship_type": value.type,
            "element_id": value.element_id,
            "start_node_element_id": value.start_node.element_id,
            "end_node_element_id": value.end_node.element_id,
            "properties": dict(value.items()),
        }
    if isinstance(value, Path):
        return {
            "type": "path",
            "nodes": [serialize_neo4j_value(node) for node in value.nodes],
            "relationships": [serialize_neo4j_value(rel) for rel in value.relationships],
        }
    if isinstance(value, dict):
        return {key: serialize_neo4j_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [serialize_neo4j_value(item) for item in value]
    if isinstance(value, tuple):
        return [serialize_neo4j_value(item) for item in value]
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if hasattr(value, "iso_format"):
        return value.iso_format()
    return value


def serialize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [serialize_neo4j_value(row) for row in rows]

