from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import pandas as pd

from kg.config import BuildConfig, load_build_config
from kg.graph_builder import BuildResult, GraphBuilder
from kg.neo4j_writer import Neo4jConfig, Neo4jWriter
from kg.rules import load_relation_rules
from env_utils import get_env, load_dotenv


load_dotenv(Path(__file__).resolve().parent)


def _build_cli_config(args: argparse.Namespace) -> BuildConfig:
    relation_csv = Path(args.relation_csv).resolve()
    params_csv = Path(args.params_csv).resolve()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None

    neo4j_cfg = None
    if args.neo4j_uri and args.neo4j_user and args.neo4j_password:
        neo4j_cfg = Neo4jConfig(
            uri=args.neo4j_uri,
            user=args.neo4j_user,
            password=args.neo4j_password,
            database=args.neo4j_database,
            batch_size=args.batch_size,
            create_constraints=args.create_constraints,
        )

    return BuildConfig(
        relation_csv=relation_csv,
        params_csv=params_csv,
        dry_run=args.dry_run,
        output_dir=output_dir,
        limit_rows=args.limit_rows,
        neo4j=neo4j_cfg,
    )


def _load_params_dataframe(csv_path: Path, limit_rows: int | None) -> pd.DataFrame:
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    if limit_rows is not None:
        return df.head(limit_rows).copy()
    return df


def _relative_text(target: Path, base_dir: Path) -> str:
    rel = os.path.relpath(str(target), str(base_dir))
    return Path(rel).as_posix()


def _build_generated_config_payload(
    *,
    relation_csv: Path,
    params_csv: Path,
    config_output_path: Path,
    output_dir_override: str | None = None,
) -> dict[str, Any]:
    config_dir = config_output_path.parent
    source_name = relation_csv.stem.replace("_relation", "")
    project_root = Path(__file__).resolve().parent
    default_run_dir = (project_root / "runs" / source_name).resolve()
    output_dir = output_dir_override or _relative_text(default_run_dir, config_dir)

    return {
        "relation_csv": _relative_text(relation_csv, config_dir),
        "params_csv": _relative_text(params_csv, config_dir),
        "dry_run": True,
        "output_dir": output_dir,
        "neo4j": {
            "uri": "${NEO4J_URI}",
            "user": "${NEO4J_USER}",
            "password": "${NEO4J_PASSWORD}",
            "database": "neo4j",
            "batch_size": 1000,
            "create_constraints": True,
        },
    }


def _generate_source_config(
    *,
    relation_csv: Path,
    params_csv: Path,
    output_path: Path,
    output_dir_override: str | None = None,
) -> None:
    payload = _build_generated_config_payload(
        relation_csv=relation_csv,
        params_csv=params_csv,
        config_output_path=output_path,
        output_dir_override=output_dir_override,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, ensure_ascii=False)
        file.write("\n")
    print(f"Generated config: {output_path}")


def _dump_artifacts(output_dir: Path, result: BuildResult) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    nodes_records = [
        {
            "label": node.label,
            "id": node.node_id,
            "properties_json": json.dumps(node.properties, ensure_ascii=False),
        }
        for node in result.nodes
    ]
    edges_records = [
        {
            "start_label": edge.start_label,
            "start_id": edge.start_id,
            "predicate": edge.predicate,
            "end_label": edge.end_label,
            "end_id": edge.end_id,
            "properties_json": json.dumps(edge.properties, ensure_ascii=False),
        }
        for edge in result.edges
    ]

    pd.DataFrame(nodes_records).to_csv(output_dir / "nodes.csv", index=False, encoding="utf-8")
    pd.DataFrame(edges_records).to_csv(output_dir / "edges.csv", index=False, encoding="utf-8")


def _print_summary(result: BuildResult) -> None:
    print("Build summary")
    print(f"- input_rows: {result.row_count}")
    print(f"- unique_nodes: {len(result.nodes)}")
    print(f"- unique_edges: {len(result.edges)}")
    if result.rule_hit_counter:
        print("- top_rule_hits:")
        for rule_id, hits in result.rule_hit_counter.most_common(10):
            print(f"  - {rule_id}: {hits}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rule-driven CSV-to-Neo4j builder for multi-source log knowledge graphs.",
    )
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument(
        "--generate-config",
        help="Write a source-specific JSON config from --relation-csv + --params-csv and exit",
    )

    parser.add_argument("--relation-csv", help="Path to relation rule CSV")
    parser.add_argument("--params-csv", help="Path to extracted params CSV")
    parser.add_argument("--output-dir", help="Optional path to save nodes/edges CSV artifacts")
    parser.add_argument(
        "--generated-output-dir",
        help="Optional output_dir value to embed into generated config",
    )

    parser.add_argument("--dry-run", action="store_true", help="Build graph in memory without Neo4j writes")
    parser.add_argument("--limit-rows", type=int, help="Optional row limit for quick tests")

    parser.add_argument("--neo4j-uri", default=get_env("NEO4J_URI"), help="Neo4j URI, e.g. bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default=get_env("NEO4J_USER"), help="Neo4j user")
    parser.add_argument("--neo4j-password", default=get_env("NEO4J_PASSWORD"), help="Neo4j password")
    parser.add_argument("--neo4j-database", default=get_env("NEO4J_DATABASE", "neo4j"), help="Neo4j database")
    parser.add_argument("--batch-size", type=int, default=1000, help="Neo4j write batch size")
    parser.add_argument(
        "--create-constraints",
        action="store_true",
        help="Create unique constraints on node id before writes",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.generate_config:
        if args.config:
            base_cfg = load_build_config(args.config)
            relation_csv = base_cfg.relation_csv
            params_csv = base_cfg.params_csv
        else:
            if not args.relation_csv or not args.params_csv:
                raise ValueError(
                    "--generate-config requires --relation-csv and --params-csv (or use --config)."
                )
            relation_csv = Path(args.relation_csv).resolve()
            params_csv = Path(args.params_csv).resolve()

        generate_path = Path(args.generate_config).resolve()
        _generate_source_config(
            relation_csv=relation_csv,
            params_csv=params_csv,
            output_path=generate_path,
            output_dir_override=args.generated_output_dir,
        )
        return

    if args.config:
        config = load_build_config(args.config)
        if args.dry_run:
            config.dry_run = True
        if args.limit_rows is not None:
            config.limit_rows = args.limit_rows
        if args.output_dir:
            config.output_dir = Path(args.output_dir).resolve()
    else:
        if not args.relation_csv or not args.params_csv:
            raise ValueError("Either --config or both --relation-csv and --params-csv are required")
        config = _build_cli_config(args)

    print(f"[1/4] Loading relation rules: {config.relation_csv}")
    rules = load_relation_rules(config.relation_csv)
    print(f"Loaded {len(rules)} rules.")

    print(f"[2/4] Loading params CSV: {config.params_csv}")
    params_df = _load_params_dataframe(config.params_csv, config.limit_rows)
    print(f"Loaded {len(params_df)} rows.")

    print("[3/4] Building graph in memory...")
    graph_builder = GraphBuilder(rules=rules)
    result = graph_builder.build(params_df)
    _print_summary(result)

    if config.output_dir is not None:
        _dump_artifacts(config.output_dir, result)
        print(f"Artifacts written to: {config.output_dir}")

    if config.dry_run:
        print("[4/4] Dry run enabled. Skip Neo4j write.")
        return

    if config.neo4j is None:
        raise ValueError("Neo4j config is missing. Provide credentials via --config or CLI args.")

    print("[4/4] Writing to Neo4j...")
    with Neo4jWriter(config.neo4j) as writer:
        if config.neo4j.create_constraints:
            writer.create_unique_constraints(result.node_labels)
            print("Unique constraints ensured.")
        writer.write_graph(result.nodes, result.edges)
    print("Neo4j write complete.")


if __name__ == "__main__":
    main()
