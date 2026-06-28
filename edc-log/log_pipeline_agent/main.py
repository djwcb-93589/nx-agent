from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .agent import AgentRunOptions, LogKgPipelineAgent
from .config import GRAPH_FUSED_DIR, GRAPH_SOURCES_DIR, PROJECT_ROOT
from .tools import ToolResult
from env_utils import get_env, load_dotenv


load_dotenv(PROJECT_ROOT)


def _result_payload(result: ToolResult) -> dict[str, Any]:
    return {
        "tool": result.tool,
        "message": result.message,
        "outputs": result.outputs,
        "metrics": result.metrics,
        "skipped": result.skipped,
    }


def _print_result(result: ToolResult) -> None:
    status = "skipped" if result.skipped else "ok"
    print(f"[{status}] {result.tool}: {result.message}")
    if result.outputs:
        for key, value in result.outputs.items():
            print(f"  {key}: {value}")
    if result.metrics:
        print(f"  metrics: {json.dumps(result.metrics, ensure_ascii=False)}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent-style orchestration for AIT logs to mapped fields, params CSV, fused KG, and graph query.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-datasets", help="List supported AIT datasets discovered in the project.")

    run_parser = subparsers.add_parser("run", help="Run the full pipeline through agent tools.")
    run_parser.add_argument("--dataset", action="append", default=[], help="Dataset name. Repeat to select several.")
    run_parser.add_argument("--force", action="store_true", help="Regenerate all file artifacts.")
    run_parser.add_argument("--force-template2samples", action="store_true")
    run_parser.add_argument("--force-pairs", action="store_true")
    run_parser.add_argument("--force-schema", action="store_true")
    run_parser.add_argument("--force-mapped-pairs", action="store_true")
    run_parser.add_argument("--force-params", action="store_true")
    run_parser.add_argument(
        "--skip-llm-steps",
        action="store_true",
        help="Require existing pairs/schema JSON and skip DeepSeek extraction/mapping.",
    )
    run_parser.add_argument("--skip-param-extraction", action="store_true")
    run_parser.add_argument("--skip-kg-build", action="store_true")
    run_parser.add_argument("--api-key", default="", help="DeepSeek API key. Pass explicitly; .env is not used for API keys.")
    run_parser.add_argument("--limit-rows", type=int, help="Only build KG from the first N params rows.")
    run_parser.add_argument(
        "--per-dataset-graph-dir",
        default=str(GRAPH_SOURCES_DIR),
    )
    run_parser.add_argument(
        "--fused-graph-dir",
        default=str(GRAPH_FUSED_DIR),
    )
    run_parser.add_argument("--write-neo4j", action="store_true", help="Write the fused graph to Neo4j.")
    run_parser.add_argument("--neo4j-uri", default=get_env("NEO4J_URI"))
    run_parser.add_argument("--neo4j-user", default=get_env("NEO4J_USER"))
    run_parser.add_argument("--neo4j-password", default=get_env("NEO4J_PASSWORD"))
    run_parser.add_argument("--neo4j-database", default=get_env("NEO4J_DATABASE", "neo4j"))
    run_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON summary.")

    query_parser = subparsers.add_parser("query", help="Ask the existing Neo4j query agent a question.")
    query_parser.add_argument("--config", required=True, help="Query agent JSON config.")
    query_parser.add_argument("--question", required=True)
    query_parser.add_argument("--refresh-schema", action="store_true")
    query_parser.add_argument("--max-result-rows", type=int)
    query_parser.add_argument("--max-answer-rows", type=int)

    artifact_query_parser = subparsers.add_parser(
        "query-artifacts",
        help="Simple local query over nodes.csv/edges.csv artifacts without Neo4j.",
    )
    artifact_query_parser.add_argument(
        "--graph-dir",
        default=str(GRAPH_FUSED_DIR),
    )
    artifact_query_parser.add_argument("--label", default="")
    artifact_query_parser.add_argument("--predicate", default="")
    artifact_query_parser.add_argument("--contains", default="")
    artifact_query_parser.add_argument("--limit", type=int, default=20)

    api_parser = subparsers.add_parser("api", help="Start the separated backend API server.")
    api_parser.add_argument("--host", default="127.0.0.1")
    api_parser.add_argument("--port", type=int, default=8787)

    frontend_parser = subparsers.add_parser("frontend", help="Start the separated static frontend server.")
    frontend_parser.add_argument("--host", default="127.0.0.1")
    frontend_parser.add_argument("--port", type=int, default=5173)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    agent = LogKgPipelineAgent()

    if args.command == "list-datasets":
        for spec in agent.datasets:
            print(
                f"{spec.name}\t{spec.family}\t{spec.csv_path.relative_to(PROJECT_ROOT)}\t"
                f"tag={spec.tag}"
            )
        return

    if args.command == "run":
        force = bool(args.force)
        options = AgentRunOptions(
            dataset_names=tuple(args.dataset),
            force_template2samples=force or args.force_template2samples,
            force_pairs=force or args.force_pairs,
            force_schema=force or args.force_schema,
            force_mapped_pairs=force or args.force_mapped_pairs,
            force_params=force or args.force_params,
            skip_llm_steps=args.skip_llm_steps,
            skip_param_extraction=args.skip_param_extraction,
            skip_kg_build=args.skip_kg_build,
            api_key=args.api_key,
            limit_rows=args.limit_rows,
            per_dataset_graph_dir=Path(args.per_dataset_graph_dir),
            fused_graph_dir=Path(args.fused_graph_dir),
            write_neo4j=args.write_neo4j,
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password,
            neo4j_database=args.neo4j_database,
        )
        outcome = agent.run(options)
        if args.json:
            payload = {
                "datasets": outcome["datasets"],
                "results": [_result_payload(item) for item in outcome["results"]],
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return

        print("Datasets: " + ", ".join(outcome["datasets"]))
        for result in outcome["results"]:
            _print_result(result)
        return

    if args.command == "query":
        result = agent.query_neo4j(
            config_path=Path(args.config),
            question=args.question,
            refresh_schema=args.refresh_schema,
            max_result_rows=args.max_result_rows,
            max_answer_rows=args.max_answer_rows,
        )
        _print_result(result)
        print()
        print(result.message)
        return

    if args.command == "query-artifacts":
        result = agent.query_artifacts(
            graph_dir=Path(args.graph_dir),
            label=args.label,
            predicate=args.predicate,
            contains=args.contains,
            limit=args.limit,
        )
        _print_result(result)
        print(result.message)
        return

    if args.command == "api":
        from .backend.server import run_server

        run_server(host=args.host, port=args.port)
        return

    if args.command == "frontend":
        from .frontend.server import run_server

        run_server(host=args.host, port=args.port)
        return

    parser.error(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    main()
