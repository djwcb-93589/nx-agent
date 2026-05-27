from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re
from typing import Any, Iterable

from neo4j import GraphDatabase

from .graph_builder import EdgeRecord, NodeRecord

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_identifier(identifier: str, kind: str) -> str:
    if not IDENTIFIER_RE.match(identifier):
        raise ValueError(f"Invalid Neo4j {kind}: '{identifier}'")
    return identifier


def _chunked(items: list[dict[str, Any]], batch_size: int) -> Iterable[list[dict[str, Any]]]:
    for index in range(0, len(items), batch_size):
        yield items[index : index + batch_size]


@dataclass(frozen=True)
class Neo4jConfig:
    uri: str
    user: str
    password: str
    database: str = "neo4j"
    batch_size: int = 1000
    create_constraints: bool = True


class Neo4jWriter:
    def __init__(self, config: Neo4jConfig) -> None:
        self.config = config
        self.driver = GraphDatabase.driver(
            config.uri,
            auth=(config.user, config.password),
        )

    def __enter__(self) -> "Neo4jWriter":
        self.driver.verify_connectivity()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.driver.close()

    def create_unique_constraints(self, labels: Iterable[str]) -> None:
        with self.driver.session(database=self.config.database) as session:
            for label in sorted(set(labels)):
                safe_label = _validate_identifier(label, "label")
                constraint_name = f"uniq_{safe_label.lower()}_id"
                query = (
                    f"CREATE CONSTRAINT {constraint_name} IF NOT EXISTS "
                    f"FOR (n:`{safe_label}`) REQUIRE n.id IS UNIQUE"
                )
                session.run(query)

    def write_graph(self, nodes: list[NodeRecord], edges: list[EdgeRecord]) -> None:
        with self.driver.session(database=self.config.database) as session:
            self._write_nodes(session, nodes)
            self._write_edges(session, edges)

    def _write_nodes(self, session, nodes: list[NodeRecord]) -> None:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for node in nodes:
            label = _validate_identifier(node.label, "label")
            grouped[label].append(
                {
                    "id": node.node_id,
                    "props": node.properties,
                }
            )

        for label, rows in grouped.items():
            query = (
                f"UNWIND $rows AS row "
                f"MERGE (n:`{label}` {{id: row.id}}) "
                f"SET n += row.props"
            )
            for batch in _chunked(rows, self.config.batch_size):
                session.run(query, rows=batch)

    def _write_edges(self, session, edges: list[EdgeRecord]) -> None:
        grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for edge in edges:
            start_label = _validate_identifier(edge.start_label, "label")
            predicate = _validate_identifier(edge.predicate, "relationship type")
            end_label = _validate_identifier(edge.end_label, "label")
            grouped[(start_label, predicate, end_label)].append(
                {
                    "start_id": edge.start_id,
                    "end_id": edge.end_id,
                    "props": edge.properties,
                }
            )

        for (start_label, predicate, end_label), rows in grouped.items():
            query = (
                f"UNWIND $rows AS row "
                f"MATCH (s:`{start_label}` {{id: row.start_id}}) "
                f"MATCH (o:`{end_label}` {{id: row.end_id}}) "
                f"MERGE (s)-[r:`{predicate}`]->(o) "
                f"SET r += row.props"
            )
            for batch in _chunked(rows, self.config.batch_size):
                session.run(query, rows=batch)

