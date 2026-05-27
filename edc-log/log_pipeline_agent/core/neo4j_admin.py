from __future__ import annotations

from typing import Any

from env_utils import get_env, load_dotenv, resolve_env_value


NEO4J_CLEAR_CONFIRMATION = "清空neo4j"


def clear_neo4j_database(payload: dict[str, Any]) -> dict[str, Any]:
    load_dotenv()
    confirmation = str(payload.get("confirmation", "")).strip()
    if confirmation != NEO4J_CLEAR_CONFIRMATION:
        raise ValueError(f"确认文本必须是：{NEO4J_CLEAR_CONFIRMATION}")

    uri = str(resolve_env_value(payload.get("neo4j_uri", "")) or get_env("NEO4J_URI")).strip()
    user = str(resolve_env_value(payload.get("neo4j_user", "")) or get_env("NEO4J_USER")).strip()
    password = str(resolve_env_value(payload.get("neo4j_password", "")) or get_env("NEO4J_PASSWORD"))
    database = str(
        resolve_env_value(payload.get("neo4j_database", "")) or get_env("NEO4J_DATABASE", "neo4j")
    ).strip() or "neo4j"
    batch_size = int(payload.get("batch_size", 10000) or 10000)
    drop_schema = bool(payload.get("drop_schema", True))
    if not uri or not user or not password:
        raise ValueError("Neo4j URI、用户和密码不能为空")
    if batch_size < 1:
        raise ValueError("batch_size must be positive")

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(uri, auth=(user, password))
    deleted_nodes = 0
    deleted_relationships = 0
    dropped_constraints: list[str] = []
    dropped_indexes: list[str] = []
    try:
        driver.verify_connectivity()
        with driver.session(database=database) as session:
            before = _count_neo4j_graph(session)

            if drop_schema:
                for name in _names(session, "SHOW CONSTRAINTS YIELD name RETURN name"):
                    session.run(f"DROP CONSTRAINT `{name}` IF EXISTS").consume()
                    dropped_constraints.append(name)

                for name in _names(session, "SHOW INDEXES YIELD name, type WHERE type <> 'LOOKUP' RETURN name"):
                    session.run(f"DROP INDEX `{name}` IF EXISTS").consume()
                    dropped_indexes.append(name)

            while True:
                deleted = _scalar(
                    session,
                    """
                    MATCH ()-[r]->()
                    WITH r LIMIT $batch_size
                    DELETE r
                    RETURN count(r) AS deleted
                    """,
                    batch_size=batch_size,
                )
                deleted_relationships += int(deleted)
                if deleted == 0:
                    break

            while True:
                deleted = _scalar(
                    session,
                    """
                    MATCH (n)
                    WITH n LIMIT $batch_size
                    DELETE n
                    RETURN count(n) AS deleted
                    """,
                    batch_size=batch_size,
                )
                deleted_nodes += int(deleted)
                if deleted == 0:
                    break

            after = _count_neo4j_graph(session)
    finally:
        driver.close()

    return {
        "database": database,
        "before": before,
        "after": after,
        "deleted_nodes": deleted_nodes,
        "deleted_relationships": deleted_relationships,
        "dropped_constraints": dropped_constraints,
        "dropped_indexes": dropped_indexes,
        "message": "Neo4j 当前数据库已清空",
    }


def _scalar(session, query: str, **params: Any) -> int:
    record = session.run(query, **params).single()
    return int(record[0]) if record else 0


def _names(session, query: str) -> list[str]:
    return [record["name"] for record in session.run(query)]


def _count_neo4j_graph(session) -> dict[str, int]:
    return {
        "nodes": _scalar(session, "MATCH (n) RETURN count(n)"),
        "relationships": _scalar(session, "MATCH ()-[r]->() RETURN count(r)"),
        "constraints": _scalar(session, "SHOW CONSTRAINTS YIELD name RETURN count(name)"),
        "indexes": _scalar(session, "SHOW INDEXES YIELD name RETURN count(name)"),
    }
