from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from neo4j import GraphDatabase

from .config import Neo4jConfig
from .schema import GraphSchema, NodeSchema, RelationshipSchema, make_graph_schema


NODE_COUNTS_QUERY = """
MATCH (n)
UNWIND labels(n) AS label
RETURN label, count(*) AS node_count
ORDER BY label
"""

NODE_PROPERTIES_QUERY = """
MATCH (n)
UNWIND labels(n) AS label
UNWIND keys(n) AS prop
RETURN label, collect(DISTINCT prop) AS properties
ORDER BY label
"""

REL_COUNTS_QUERY = """
MATCH (a)-[r]->(b)
RETURN labels(a)[0] AS start_label, type(r) AS rel_type, labels(b)[0] AS end_label, count(*) AS rel_count
ORDER BY start_label, rel_type, end_label
"""

REL_PROPERTIES_QUERY = """
MATCH (a)-[r]->(b)
UNWIND CASE WHEN size(keys(r)) = 0 THEN [NULL] ELSE keys(r) END AS prop
RETURN labels(a)[0] AS start_label, type(r) AS rel_type, labels(b)[0] AS end_label, collect(DISTINCT prop) AS properties
ORDER BY start_label, rel_type, end_label
"""


@dataclass(frozen=True)
class QueryExecutionResult:
    rows: list[dict[str, Any]]
    truncated: bool


class Neo4jGraphClient:
    def __init__(self, config: Neo4jConfig) -> None:
        self.config = config
        self.driver = GraphDatabase.driver(
            config.uri,
            auth=(config.user, config.password),
        )

    def __enter__(self) -> "Neo4jGraphClient":
        self.driver.verify_connectivity()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.driver.close()

    def extract_schema(self) -> GraphSchema:
        with self.driver.session(database=self.config.database) as session:
            node_counts = {
                record["label"]: int(record["node_count"])
                for record in session.run(NODE_COUNTS_QUERY)
            }
            node_props = {
                record["label"]: sorted(str(prop) for prop in record["properties"] if prop is not None)
                for record in session.run(NODE_PROPERTIES_QUERY)
            }
            rel_counts = {
                (record["start_label"], record["rel_type"], record["end_label"]): int(record["rel_count"])
                for record in session.run(REL_COUNTS_QUERY)
            }
            rel_props = {
                (record["start_label"], record["rel_type"], record["end_label"]): sorted(
                    str(prop) for prop in record["properties"] if prop is not None
                )
                for record in session.run(REL_PROPERTIES_QUERY)
            }

        nodes = [
            NodeSchema(label=label, properties=node_props.get(label, []), count=count)
            for label, count in node_counts.items()
        ]
        relationships = [
            RelationshipSchema(
                start_label=start_label,
                rel_type=rel_type,
                end_label=end_label,
                properties=rel_props.get((start_label, rel_type, end_label), []),
                count=count,
            )
            for (start_label, rel_type, end_label), count in rel_counts.items()
        ]
        return make_graph_schema(nodes, relationships)

    def run_read_query(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
        max_rows: int = 50,
    ) -> QueryExecutionResult:
        params = parameters or {}
        rows: list[dict[str, Any]] = []
        truncated = False

        with self.driver.session(database=self.config.database) as session:
            result = session.run(cypher, parameters=params)
            for index, record in enumerate(result):
                if index >= max_rows:
                    truncated = True
                    break
                rows.append(record.data())

        return QueryExecutionResult(rows=rows, truncated=truncated)

