from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Callable

from ..agent import AgentRunOptions
from ..config import DatasetSpec, PROJECT_ROOT, discover_dataset_specs
from ..tools import (
    ToolResult,
    build_graph_for_dataset,
    dump_graph_artifacts,
    extract_field_semantics,
    extract_params_from_logs,
    fuse_graph_results,
    generate_template2samples,
    map_fields_to_poi_schema,
    merge_pairs_with_schema_mapping,
    write_graph_to_neo4j,
)
from .dag import PipelineNode, PipelinePlan
from .evaluator import ArtifactEvaluator
from .memory import RunMemory
from env_utils import get_env, resolve_env_value


ProgressCallback = Callable[[str, dict[str, Any]], None]


class DagPipelineExecutor:
    def __init__(self, specs: list[DatasetSpec] | None = None) -> None:
        self.specs = specs if specs is not None else discover_dataset_specs()
        self.by_name = {spec.name: spec for spec in self.specs}

    def execute(
        self,
        plan: PipelinePlan,
        options: AgentRunOptions,
        *,
        progress_callback: ProgressCallback | None = None,
        memory: RunMemory | None = None,
    ) -> dict[str, Any]:
        memory = memory or RunMemory()
        memory.write_json("plan.json", plan.to_dict())
        self._emit(progress_callback, memory, "plan_started", plan.to_dict())

        tool_results: list[ToolResult] = []
        graph_results: list[tuple[str, Any]] = []
        fused_graph = None
        node_status: dict[str, dict[str, Any]] = {}

        max_workers = max(1, int(plan.options.get("max_workers", 1) or 1))
        pending = {node.id: node for node in plan.topological_nodes()}
        completed: set[str] = set()
        running: dict[Future[tuple[ToolResult, Any]], PipelineNode] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while pending or running:
                slots = max_workers - len(running)
                ready = [
                    node
                    for node in pending.values()
                    if slots > 0 and all(dep in completed for dep in node.deps)
                ]

                for node in sorted(ready, key=lambda item: item.id)[:slots]:
                    pending.pop(node.id)
                    self._emit(progress_callback, memory, "node_started", node.to_dict())
                    running[
                        executor.submit(self._execute_node, node, options, graph_results, fused_graph)
                    ] = node

                if not running:
                    unresolved = ", ".join(sorted(pending))
                    raise ValueError(f"Pipeline plan cannot progress; unresolved nodes: {unresolved}")

                done_futures, _ = wait(running, return_when=FIRST_COMPLETED)
                for future in done_futures:
                    node = running.pop(future)
                    try:
                        result, payload = future.result()
                        if node.tool == "build_graph_for_dataset":
                            graph_results.append((node.dataset, payload))
                        elif node.tool == "fuse_graph_results":
                            fused_graph = payload

                        tool_results.append(result)
                        result_payload = self._tool_result_payload(result)
                        node_status[node.id] = {"status": "completed", "result": result_payload}
                        completed.add(node.id)
                        self._emit(
                            progress_callback,
                            memory,
                            "node_finished",
                            {
                                "node": node.to_dict(),
                                "result": result_payload,
                            },
                        )
                    except Exception as exc:
                        node_status[node.id] = {"status": "failed", "error": str(exc)}
                        self._emit(
                            progress_callback,
                            memory,
                            "node_failed",
                            {
                                "node": node.to_dict(),
                                "error": str(exc),
                            },
                        )
                        if node.optional:
                            completed.add(node.id)
                        else:
                            raise

        evaluation = {}
        if fused_graph is not None:
            evaluation = ArtifactEvaluator().evaluate_graph_dir(options.fused_graph_dir).to_dict()
            memory.write_json("validation_report.json", evaluation)

        outcome = {
            "plan": plan.to_dict(),
            "results": [self._tool_result_payload(result) for result in tool_results],
            "node_status": node_status,
            "evaluation": evaluation,
            "run_dir": str(memory.run_dir),
        }
        memory.write_json("outcome.json", outcome)
        memory.write_summary(self._summary_lines(outcome))
        self._emit(progress_callback, memory, "plan_finished", outcome)
        return outcome

    def _execute_node(
        self,
        node: PipelineNode,
        options: AgentRunOptions,
        graph_results: list[tuple[str, Any]],
        fused_graph: Any,
    ) -> tuple[ToolResult, Any]:
        spec = self.by_name.get(node.dataset) if node.dataset != "all" else None

        if node.tool == "generate_template2samples":
            assert spec is not None
            result = generate_template2samples([spec], force=options.force_template2samples)[0]
            return result, None
        if node.tool == "extract_field_semantics":
            assert spec is not None
            result = extract_field_semantics(spec, force=options.force_pairs, api_key=options.api_key)
            return result, None
        if node.tool == "map_fields_to_poi_schema":
            assert spec is not None
            result = map_fields_to_poi_schema(spec, force=options.force_schema, api_key=options.api_key)
            return result, None
        if node.tool == "merge_pairs_with_schema_mapping":
            assert spec is not None
            result = merge_pairs_with_schema_mapping(spec, force=options.force_mapped_pairs)
            return result, None
        if node.tool == "extract_params_from_logs":
            assert spec is not None
            result = extract_params_from_logs(spec, force=options.force_params, api_key=options.api_key)
            return result, None
        if node.tool == "build_graph_for_dataset":
            assert spec is not None
            result, graph = build_graph_for_dataset(
                spec,
                output_dir=options.per_dataset_graph_dir / spec.name,
                limit_rows=options.limit_rows,
            )
            return result, graph
        if node.tool == "fuse_graph_results":
            graph = fuse_graph_results(graph_results)
            dump_graph_artifacts(options.fused_graph_dir, graph)
            result = ToolResult(
                tool="fuse_graph_results",
                message="Fused all selected dataset graphs",
                outputs={"graph_dir": str(options.fused_graph_dir.resolve())},
                metrics={
                    "input_rows": graph.row_count,
                    "unique_nodes": len(graph.nodes),
                    "unique_edges": len(graph.edges),
                },
            )
            return result, graph
        if node.tool == "write_graph_to_neo4j":
            if fused_graph is None:
                raise ValueError("Cannot write Neo4j before fused graph is available")
            uri = str(resolve_env_value(options.neo4j_uri) or get_env("NEO4J_URI"))
            user = str(resolve_env_value(options.neo4j_user) or get_env("NEO4J_USER"))
            password = str(resolve_env_value(options.neo4j_password) or get_env("NEO4J_PASSWORD"))
            database = str(resolve_env_value(options.neo4j_database) or get_env("NEO4J_DATABASE", "neo4j"))
            if not uri or not user or not password:
                raise ValueError("Neo4j URI, user, and password must be configured in .env or request payload")
            result = write_graph_to_neo4j(
                fused_graph,
                uri=uri,
                user=user,
                password=password,
                database=database,
            )
            return result, None

        raise ValueError(f"Unsupported pipeline node tool: {node.tool}")

    @staticmethod
    def _emit(
        progress_callback: ProgressCallback | None,
        memory: RunMemory,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        memory.append_event(event_type, payload)
        if progress_callback is not None:
            progress_callback(event_type, payload)

    @staticmethod
    def _tool_result_payload(result: ToolResult) -> dict[str, Any]:
        return {
            "tool": result.tool,
            "message": result.message,
            "outputs": result.outputs,
            "metrics": result.metrics,
            "skipped": result.skipped,
        }

    @staticmethod
    def _summary_lines(outcome: dict[str, Any]) -> list[str]:
        plan = outcome.get("plan", {})
        evaluation = outcome.get("evaluation", {})
        summary = evaluation.get("summary", {}) if isinstance(evaluation, dict) else {}
        return [
            f"# Pipeline Run {plan.get('plan_id', '')}",
            "",
            f"- Goal: {plan.get('goal', '')}",
            f"- Nodes: {len(plan.get('nodes', []))}",
            f"- Results: {len(outcome.get('results', []))}",
            f"- Validation errors: {summary.get('error', 0)}",
            f"- Validation warnings: {summary.get('warning', 0)}",
        ]
