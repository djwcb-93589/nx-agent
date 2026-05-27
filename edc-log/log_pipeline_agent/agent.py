from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .config import AIT_ROOT, GRAPH_FUSED_DIR, GRAPH_SOURCES_DIR, PROJECT_ROOT, DatasetSpec, discover_dataset_specs
from .tools import (
    ToolResult,
    build_graph_for_dataset,
    extract_field_semantics,
    extract_params_from_logs,
    fuse_graph_results,
    generate_template2samples,
    map_fields_to_poi_schema,
    merge_pairs_with_schema_mapping,
    query_graph_artifacts,
    query_neo4j_graph,
    write_graph_to_neo4j,
)
from env_utils import get_env, resolve_env_value


ProgressCallback = Callable[[str, dict[str, Any]], None]


@dataclass
class AgentRunOptions:
    dataset_names: tuple[str, ...] = ()
    force_template2samples: bool = False
    force_pairs: bool = False
    force_schema: bool = False
    force_mapped_pairs: bool = False
    force_params: bool = False
    skip_llm_steps: bool = False
    skip_param_extraction: bool = False
    skip_kg_build: bool = False
    api_key: str = ""
    limit_rows: int | None = None
    per_dataset_graph_dir: Path = GRAPH_SOURCES_DIR
    fused_graph_dir: Path = GRAPH_FUSED_DIR
    write_neo4j: bool = False
    neo4j_uri: str = ""
    neo4j_user: str = ""
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"


class LogKgPipelineAgent:
    def __init__(self, *, ait_root: Path = AIT_ROOT) -> None:
        self.ait_root = ait_root.resolve()
        self._datasets = discover_dataset_specs(self.ait_root)

    @property
    def datasets(self) -> list[DatasetSpec]:
        return list(self._datasets)

    def select_datasets(self, names: tuple[str, ...] = ()) -> list[DatasetSpec]:
        if not names:
            return self.datasets

        by_name = {spec.name: spec for spec in self._datasets}
        missing = sorted(set(names) - set(by_name))
        if missing:
            known = ", ".join(sorted(by_name))
            raise ValueError(f"Unknown dataset name(s): {', '.join(missing)}. Known: {known}")
        return [by_name[name] for name in names]

    def run(
        self,
        options: AgentRunOptions,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        selected = self.select_datasets(options.dataset_names)
        all_results: list[ToolResult] = []
        per_dataset_graphs: list[tuple[str, Any]] = []

        self._emit(
            progress_callback,
            "run_started",
            {
                "datasets": [spec.name for spec in selected],
                "dataset_count": len(selected),
            },
        )

        self._emit(
            progress_callback,
            "step_started",
            {
                "tool": "generate_template2samples",
                "dataset": "all",
                "message": "解析 AIT/3.csv 并生成 template2samples.json",
            },
        )
        template_results = generate_template2samples(
            selected,
            force=options.force_template2samples,
        )
        for result in template_results:
            all_results.append(result)
            self._emit_result(progress_callback, result)

        for spec in selected:
            self._emit(
                progress_callback,
                "dataset_started",
                {
                    "dataset": spec.name,
                    "family": spec.family,
                    "csv_path": str(spec.csv_path),
                },
            )
            if not options.skip_llm_steps:
                self._emit(
                    progress_callback,
                    "step_started",
                    {
                        "tool": "extract_field_semantics",
                        "dataset": spec.name,
                        "message": "调用 DeepSeek 抽取字段及语义",
                    },
                )
                result = extract_field_semantics(
                    spec,
                    force=options.force_pairs,
                    api_key=options.api_key,
                )
                all_results.append(result)
                self._emit_result(progress_callback, result)

                self._emit(
                    progress_callback,
                    "step_started",
                    {
                        "tool": "map_fields_to_poi_schema",
                        "dataset": spec.name,
                        "message": "根据 POI schema 完成语义映射",
                    },
                )
                result = map_fields_to_poi_schema(
                    spec,
                    force=options.force_schema,
                    api_key=options.api_key,
                )
                all_results.append(result)
                self._emit_result(progress_callback, result)
            else:
                self._require_existing(spec.pairs_path, "pairs JSON")
                self._require_existing(spec.schema_path, "schema JSON")
                self._emit(
                    progress_callback,
                    "step_skipped",
                    {
                        "tool": "llm_steps",
                        "dataset": spec.name,
                        "message": "已跳过 DeepSeek 字段抽取和 POI 映射，使用现有 JSON",
                    },
                )

            self._emit(
                progress_callback,
                "step_started",
                {
                    "tool": "merge_pairs_with_schema_mapping",
                    "dataset": spec.name,
                    "message": "合并字段语义 JSON 和 schema 映射 JSON",
                },
            )
            result = merge_pairs_with_schema_mapping(
                spec,
                force=options.force_mapped_pairs,
            )
            all_results.append(result)
            self._emit_result(progress_callback, result)

            if not options.skip_param_extraction:
                self._emit(
                    progress_callback,
                    "step_started",
                    {
                        "tool": "extract_params_from_logs",
                        "dataset": spec.name,
                        "message": "回到原始日志抽取字段参数",
                    },
                )
                result = extract_params_from_logs(
                    spec,
                    force=options.force_params,
                    api_key=options.api_key,
                )
                all_results.append(result)
                self._emit_result(progress_callback, result)
            else:
                self._require_existing(spec.params_output_path, "params CSV")
                self._emit(
                    progress_callback,
                    "step_skipped",
                    {
                        "tool": "extract_params_from_logs",
                        "dataset": spec.name,
                        "message": "已跳过参数抽取，使用现有 params CSV",
                    },
                )

            if not options.skip_kg_build:
                self._emit(
                    progress_callback,
                    "step_started",
                    {
                        "tool": "build_graph_for_dataset",
                        "dataset": spec.name,
                        "message": "根据 relation.csv 构建单源知识图谱",
                    },
                )
                source_graph_dir = options.per_dataset_graph_dir / spec.name
                result, graph = build_graph_for_dataset(
                    spec,
                    output_dir=source_graph_dir,
                    limit_rows=options.limit_rows,
                )
                all_results.append(result)
                per_dataset_graphs.append((spec.name, graph))
                self._emit_result(progress_callback, result)
            else:
                self._emit(
                    progress_callback,
                    "step_skipped",
                    {
                        "tool": "build_graph_for_dataset",
                        "dataset": spec.name,
                        "message": "已跳过知识图谱构建",
                    },
                )

        fused_result = None
        if per_dataset_graphs:
            self._emit(
                progress_callback,
                "step_started",
                {
                    "tool": "fuse_graph_results",
                    "dataset": "all",
                    "message": "融合所有日志源知识图谱",
                },
            )
            fused_result = fuse_graph_results(per_dataset_graphs)
            from .tools import dump_graph_artifacts

            dump_graph_artifacts(options.fused_graph_dir, fused_result)
            result = ToolResult(
                tool="fuse_graph_results",
                message="Fused all selected dataset graphs",
                outputs={"graph_dir": str(options.fused_graph_dir.resolve())},
                metrics={
                    "input_rows": fused_result.row_count,
                    "unique_nodes": len(fused_result.nodes),
                    "unique_edges": len(fused_result.edges),
                },
            )
            all_results.append(result)
            self._emit_result(progress_callback, result)

            if options.write_neo4j:
                neo4j_uri = str(resolve_env_value(options.neo4j_uri) or get_env("NEO4J_URI"))
                neo4j_user = str(resolve_env_value(options.neo4j_user) or get_env("NEO4J_USER"))
                neo4j_password = str(resolve_env_value(options.neo4j_password) or get_env("NEO4J_PASSWORD"))
                neo4j_database = str(
                    resolve_env_value(options.neo4j_database) or get_env("NEO4J_DATABASE", "neo4j")
                )
                if not neo4j_uri or not neo4j_user or not neo4j_password:
                    raise ValueError("--write-neo4j requires uri, user, and password")
                self._emit(
                    progress_callback,
                    "step_started",
                    {
                        "tool": "write_graph_to_neo4j",
                        "dataset": "all",
                        "message": "写入融合图谱到 Neo4j",
                    },
                )
                result = write_graph_to_neo4j(
                    fused_result,
                    uri=neo4j_uri,
                    user=neo4j_user,
                    password=neo4j_password,
                    database=neo4j_database,
                )
                all_results.append(result)
                self._emit_result(progress_callback, result)

        self._emit(
            progress_callback,
            "run_finished",
            {
                "datasets": [spec.name for spec in selected],
                "result_count": len(all_results),
            },
        )

        return {
            "datasets": [spec.name for spec in selected],
            "results": all_results,
            "fused_graph": fused_result,
        }

    def query_neo4j(
        self,
        *,
        config_path: Path,
        question: str,
        refresh_schema: bool = False,
        max_result_rows: int | None = None,
        max_answer_rows: int | None = None,
    ) -> ToolResult:
        return query_neo4j_graph(
            config_path=config_path,
            question=question,
            refresh_schema=refresh_schema,
            max_result_rows=max_result_rows,
            max_answer_rows=max_answer_rows,
        )

    def query_artifacts(
        self,
        *,
        graph_dir: Path,
        label: str = "",
        predicate: str = "",
        contains: str = "",
        limit: int = 20,
    ) -> ToolResult:
        return query_graph_artifacts(
            graph_dir=graph_dir,
            label=label,
            predicate=predicate,
            contains=contains,
            limit=limit,
        )

    @staticmethod
    def _require_existing(path: Path, artifact_name: str) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Missing {artifact_name}: {path}")

    @staticmethod
    def _emit(
        progress_callback: ProgressCallback | None,
        event: str,
        payload: dict[str, Any],
    ) -> None:
        if progress_callback is not None:
            progress_callback(event, payload)

    @classmethod
    def _emit_result(
        cls,
        progress_callback: ProgressCallback | None,
        result: ToolResult,
    ) -> None:
        cls._emit(
            progress_callback,
            "tool_result",
            {
                "tool": result.tool,
                "message": result.message,
                "outputs": result.outputs,
                "metrics": result.metrics,
                "skipped": result.skipped,
            },
        )
