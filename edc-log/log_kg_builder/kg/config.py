from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .neo4j_writer import Neo4jConfig
from env_utils import load_dotenv, resolve_env_value

ENV_PATTERN_PREFIX = "${"
ENV_PATTERN_SUFFIX = "}"


@dataclass
class BuildConfig:
    relation_csv: Path
    params_csv: Path
    dry_run: bool = False
    output_dir: Path | None = None
    limit_rows: int | None = None
    neo4j: Neo4jConfig | None = None


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


def load_build_config(config_path: str | Path) -> BuildConfig:
    load_dotenv()
    path = Path(config_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)

    base_dir = path.parent
    relation_csv = _resolve_path(base_dir, raw.get("relation_csv"))
    params_csv = _resolve_path(base_dir, raw.get("params_csv"))
    output_dir = _resolve_path(base_dir, raw.get("output_dir"))

    if relation_csv is None or params_csv is None:
        raise ValueError("Both relation_csv and params_csv must be provided in config")

    neo4j_cfg = None
    raw_neo4j = raw.get("neo4j")
    if isinstance(raw_neo4j, dict):
        uri = _resolve_env_value(raw_neo4j.get("uri"))
        user = _resolve_env_value(raw_neo4j.get("user"))
        password = _resolve_env_value(raw_neo4j.get("password"))
        database = _resolve_env_value(raw_neo4j.get("database")) or "neo4j"
        batch_size = int(raw_neo4j.get("batch_size", 1000))
        create_constraints = bool(raw_neo4j.get("create_constraints", True))

        if uri and user and password:
            neo4j_cfg = Neo4jConfig(
                uri=str(uri),
                user=str(user),
                password=str(password),
                database=str(database),
                batch_size=batch_size,
                create_constraints=create_constraints,
            )

    return BuildConfig(
        relation_csv=relation_csv,
        params_csv=params_csv,
        dry_run=bool(raw.get("dry_run", False)),
        output_dir=output_dir,
        limit_rows=int(raw["limit_rows"]) if raw.get("limit_rows") is not None else None,
        neo4j=neo4j_cfg,
    )
