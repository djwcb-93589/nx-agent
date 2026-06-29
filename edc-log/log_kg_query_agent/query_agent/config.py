from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from env_utils import load_dotenv, resolve_env_value


ENV_PATTERN_PREFIX = "${"
ENV_PATTERN_SUFFIX = "}"


@dataclass(frozen=True)
class Neo4jConfig:
    uri: str
    user: str
    password: str
    database: str = "neo4j"


@dataclass(frozen=True)
class LLMConfig:
    api_key: str
    base_url: str = "https://api.deepseek.com"
    cypher_model: str = "deepseek-v4-flash"
    answer_model: str = "deepseek-v4-flash"
    temperature: float = 0.1
    max_tokens: int = 2000
    timeout_seconds: int = 120


@dataclass(frozen=True)
class QueryRuntimeConfig:
    schema_cache_path: Path
    run_output_dir: Path | None = None
    auto_refresh_schema: bool = True
    max_result_rows: int = 50
    max_answer_rows: int = 20
    max_repair_attempts: int = 1


@dataclass(frozen=True)
class QueryAgentConfig:
    neo4j: Neo4jConfig
    llm: LLMConfig
    runtime: QueryRuntimeConfig


def _resolve_env_value(value: Any) -> Any:
    load_dotenv()
    if isinstance(value, str):
        text = value.strip()
        if text.startswith(ENV_PATTERN_PREFIX) and text.endswith(ENV_PATTERN_SUFFIX):
            return resolve_env_value(text, "")
    return value


def _resolve_path(base_dir: Path, raw_path: str | None) -> Path | None:
    if not raw_path:
        return None
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return (base_dir / path).resolve()


def load_query_agent_config(
    config_path: str | Path,
    *,
    require_llm_api_key: bool = True,
) -> QueryAgentConfig:
    load_dotenv()
    path = Path(config_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)

    base_dir = path.parent
    neo4j_raw = raw.get("neo4j") or {}
    llm_raw = raw.get("llm") or {}
    runtime_raw = raw.get("runtime") or {}

    neo4j = Neo4jConfig(
        uri=str(_resolve_env_value(neo4j_raw.get("uri", ""))),
        user=str(_resolve_env_value(neo4j_raw.get("user", ""))),
        password=str(_resolve_env_value(neo4j_raw.get("password", ""))),
        database=str(_resolve_env_value(neo4j_raw.get("database", "neo4j")) or "neo4j"),
    )
    if not neo4j.uri or not neo4j.user or not neo4j.password:
        raise ValueError("neo4j.uri, neo4j.user and neo4j.password must be configured")

    llm = LLMConfig(
        api_key=str(_resolve_env_value(llm_raw.get("api_key", ""))),
        base_url=str(_resolve_env_value(llm_raw.get("base_url", "https://api.deepseek.com"))),
        cypher_model=str(_resolve_env_value(llm_raw.get("cypher_model", "deepseek-v4-flash"))),
        answer_model=str(_resolve_env_value(llm_raw.get("answer_model", "deepseek-v4-flash"))),
        temperature=float(llm_raw.get("temperature", 0.1)),
        max_tokens=int(llm_raw.get("max_tokens", 2000)),
        timeout_seconds=int(llm_raw.get("timeout_seconds", 120)),
    )
    if require_llm_api_key and not llm.api_key:
        raise ValueError("llm.api_key must be configured")

    schema_cache_path = _resolve_path(base_dir, runtime_raw.get("schema_cache_path")) or (
        path.parent.parent / "cache" / "graph_schema.json"
    ).resolve()
    run_output_dir = _resolve_path(base_dir, runtime_raw.get("run_output_dir"))

    runtime = QueryRuntimeConfig(
        schema_cache_path=schema_cache_path,
        run_output_dir=run_output_dir,
        auto_refresh_schema=bool(runtime_raw.get("auto_refresh_schema", True)),
        max_result_rows=int(runtime_raw.get("max_result_rows", 50)),
        max_answer_rows=int(runtime_raw.get("max_answer_rows", 20)),
        max_repair_attempts=int(runtime_raw.get("max_repair_attempts", 1)),
    )

    return QueryAgentConfig(neo4j=neo4j, llm=llm, runtime=runtime)
