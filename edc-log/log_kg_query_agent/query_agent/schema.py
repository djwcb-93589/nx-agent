from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


@dataclass(frozen=True)
class NodeSchema:
    label: str
    properties: list[str]
    count: int


@dataclass(frozen=True)
class RelationshipSchema:
    start_label: str
    rel_type: str
    end_label: str
    properties: list[str]
    count: int


@dataclass(frozen=True)
class GraphSchema:
    generated_at_utc: str
    nodes: list[NodeSchema]
    relationships: list[RelationshipSchema]

    @property
    def labels(self) -> set[str]:
        return {node.label for node in self.nodes}

    @property
    def relationship_types(self) -> set[str]:
        return {rel.rel_type for rel in self.relationships}

    @property
    def property_names(self) -> set[str]:
        node_props = {prop for node in self.nodes for prop in node.properties}
        rel_props = {prop for rel in self.relationships for prop in rel.properties}
        return node_props | rel_props

    def to_dict(self) -> dict:
        return {
            "generated_at_utc": self.generated_at_utc,
            "nodes": [
                {"label": node.label, "properties": node.properties, "count": node.count}
                for node in self.nodes
            ],
            "relationships": [
                {
                    "start_label": rel.start_label,
                    "rel_type": rel.rel_type,
                    "end_label": rel.end_label,
                    "properties": rel.properties,
                    "count": rel.count,
                }
                for rel in self.relationships
            ],
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "GraphSchema":
        return cls(
            generated_at_utc=str(raw.get("generated_at_utc", "")),
            nodes=[
                NodeSchema(
                    label=str(item["label"]),
                    properties=sorted(str(prop) for prop in item.get("properties", [])),
                    count=int(item.get("count", 0)),
                )
                for item in raw.get("nodes", [])
            ],
            relationships=[
                RelationshipSchema(
                    start_label=str(item["start_label"]),
                    rel_type=str(item["rel_type"]),
                    end_label=str(item["end_label"]),
                    properties=sorted(str(prop) for prop in item.get("properties", [])),
                    count=int(item.get("count", 0)),
                )
                for item in raw.get("relationships", [])
            ],
        )

    def to_prompt_text(self) -> str:
        node_lines = []
        for node in self.nodes:
            props = ", ".join(node.properties) if node.properties else "(no properties)"
            node_lines.append(f"- {node.label} [{node.count}] properties: {props}")

        rel_lines = []
        for rel in self.relationships:
            props = ", ".join(rel.properties) if rel.properties else "(no properties)"
            rel_lines.append(
                f"- {rel.start_label} -[{rel.rel_type}]-> {rel.end_label} "
                f"[{rel.count}] properties: {props}"
            )

        node_block = "\n".join(node_lines) if node_lines else "- none"
        rel_block = "\n".join(rel_lines) if rel_lines else "- none"
        return (
            f"Schema generated at UTC {self.generated_at_utc}\n"
            f"Node labels:\n{node_block}\n\n"
            f"Relationship patterns:\n{rel_block}"
        )


def make_graph_schema(nodes: list[NodeSchema], relationships: list[RelationshipSchema]) -> GraphSchema:
    return GraphSchema(
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        nodes=sorted(nodes, key=lambda item: item.label),
        relationships=sorted(
            relationships,
            key=lambda item: (item.start_label, item.rel_type, item.end_label),
        ),
    )


def save_graph_schema(schema: GraphSchema, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(schema.to_dict(), file, indent=2, ensure_ascii=False)
        file.write("\n")


def load_graph_schema(path: Path) -> GraphSchema:
    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)
    return GraphSchema.from_dict(raw)

