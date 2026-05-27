from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from ..agent import AgentRunOptions
from ..config import GRAPH_FUSED_DIR, GRAPH_SOURCES_DIR, PROJECT_ROOT, DatasetSpec, discover_dataset_specs
from .dag import PipelineNode, PipelinePlan
from .preflight import PreflightAnalyzer, PreflightReport


@dataclass
class PlannerRequest:
    task: str = ""
    datasets: tuple[str, ...] = ()
    force: bool = False
    skip_llm_steps: bool | None = None
    skip_param_extraction: bool | None = None
    skip_kg_build: bool | None = None
    write_neo4j: bool = False
    limit_rows: int | None = None
    api_key: str = ""
    fused_graph_dir: str = ""
    per_dataset_graph_dir: str = ""
    neo4j_uri: str = ""
    neo4j_user: str = ""
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"
    max_workers: int = 1


class SmartPipelinePlanner:
    def __init__(self, specs: list[DatasetSpec] | None = None) -> None:
        self.specs = specs if specs is not None else discover_dataset_specs()

    def build_plan(
        self,
        request: PlannerRequest,
        *,
        preflight: PreflightReport | None = None,
    ) -> PipelinePlan:
        selected = self._select_datasets(request)
        preflight = preflight or PreflightAnalyzer(selected).run(tuple(spec.name for spec in selected))
        inferred = self._infer_options(request, preflight)

        nodes: list[PipelineNode] = []
        decisions: list[str] = list(inferred["decisions"])
        warnings = list(preflight.warnings)
        confirmations: list[dict[str, Any]] = []
        artifacts = {
            dataset.name: dataset.artifacts
            for dataset in preflight.datasets
        }

        last_graph_nodes: list[str] = []
        for spec in selected:
            state = artifacts.get(spec.name, {})
            force = bool(inferred["force"])
            has_template = self._artifact_exists(state, "template2samples")
            has_pairs = self._artifact_exists(state, "pairs")
            has_schema = self._artifact_exists(state, "schema")
            has_mapped = self._artifact_exists(state, "mapped_pairs")
            has_params = self._artifact_exists(state, "params_csv")

            need_params = not inferred["skip_param_extraction"] and (force or not has_params)
            need_mapped = need_params and (force or not has_mapped)
            need_schema = (
                need_mapped
                and not inferred["skip_llm_steps"]
                and (force or not has_schema)
            )
            need_pairs = (
                need_mapped
                and not inferred["skip_llm_steps"]
                and (force or not has_pairs)
            )
            need_template = need_pairs and (force or not has_template)

            if not need_template and has_template:
                decisions.append(f"{spec.name}: template2samples 已存在，计划跳过模板采样")
            if inferred["skip_llm_steps"]:
                decisions.append(f"{spec.name}: pairs/schema 已存在或任务要求复用，计划跳过 DeepSeek 字段抽取和 POI 映射")
            else:
                if not need_pairs and has_pairs:
                    decisions.append(f"{spec.name}: pairs JSON 已存在，计划跳过字段语义抽取")
                if not need_schema and has_schema:
                    decisions.append(f"{spec.name}: schema JSON 已存在，计划跳过 POI 映射")
            if not need_mapped and has_mapped:
                decisions.append(f"{spec.name}: mapped JSON 已存在且本轮无需重新合并")
            if inferred["skip_param_extraction"]:
                decisions.append(f"{spec.name}: params CSV 已存在或任务要求复用，计划跳过参数抽取")

            template_id = self._node_id(spec.name, "template")
            if need_template:
                nodes.append(
                    PipelineNode(
                        id=template_id,
                        tool="generate_template2samples",
                        dataset=spec.name,
                        reason="AIT/3.csv 尚未具备可复用 template2samples.json，需要先转换",
                    )
                )

            pairs_id = self._node_id(spec.name, "pairs")
            schema_id = self._node_id(spec.name, "schema")
            if need_pairs:
                pairs_deps = (template_id,) if need_template else ()
                nodes.append(
                    PipelineNode(
                        id=pairs_id,
                        tool="extract_field_semantics",
                        dataset=spec.name,
                        deps=pairs_deps,
                        reason="缺少可复用 pairs JSON，需要使用 DeepSeek 抽取字段及语义",
                    )
                )
            if need_schema:
                schema_deps = (pairs_id,) if need_pairs else ()
                nodes.append(
                    PipelineNode(
                        id=schema_id,
                        tool="map_fields_to_poi_schema",
                        dataset=spec.name,
                        deps=schema_deps,
                        reason="缺少可复用 schema JSON，需要将字段映射到 POI schema",
                    )
                )

            mapped_id = self._node_id(spec.name, "mapped")
            if need_mapped:
                mapped_deps = tuple(
                    dep
                    for dep, needed in ((pairs_id, need_pairs), (schema_id, need_schema))
                    if needed
                )
                nodes.append(
                    PipelineNode(
                        id=mapped_id,
                        tool="merge_pairs_with_schema_mapping",
                        dataset=spec.name,
                        deps=mapped_deps,
                        reason="缺少可复用 mapped JSON，需要合并字段语义和 POI 映射",
                    )
                )

            graph_deps: tuple[str, ...] = ()
            if need_params:
                params_id = self._node_id(spec.name, "params")
                nodes.append(
                    PipelineNode(
                        id=params_id,
                        tool="extract_params_from_logs",
                        dataset=spec.name,
                        deps=(mapped_id,) if need_mapped else (),
                        reason="缺少可复用 params CSV，需要从原始日志抽取字段参数",
                    )
                )
                graph_deps = (params_id,)

            if not inferred["skip_kg_build"]:
                graph_id = self._node_id(spec.name, "graph")
                nodes.append(
                    PipelineNode(
                        id=graph_id,
                        tool="build_graph_for_dataset",
                        dataset=spec.name,
                        deps=graph_deps,
                        reason="依据 relation.csv 构建单源知识图谱",
                    )
                )
                last_graph_nodes.append(graph_id)
            else:
                decisions.append(f"{spec.name}: 任务要求跳过图谱构建")

        if last_graph_nodes:
            nodes.append(
                PipelineNode(
                    id="all__fuse_graph",
                    tool="fuse_graph_results",
                    dataset="all",
                    deps=tuple(last_graph_nodes),
                    reason="融合所有成功的数据源图谱",
                )
            )
            if inferred["write_neo4j"]:
                nodes.append(
                    PipelineNode(
                        id="all__write_neo4j",
                        tool="write_graph_to_neo4j",
                        dataset="all",
                        deps=("all__fuse_graph",),
                        reason="将融合图谱写入 Neo4j",
                    )
                )

        if inferred["write_neo4j"]:
            confirmations.append(
                {
                    "type": "neo4j_write",
                    "message": "写入 Neo4j 可能与现有图数据合并，请确认目标库状态。",
                    "required": True,
                }
            )
        if inferred["force"]:
            confirmations.append(
                {
                    "type": "overwrite_artifacts",
                    "message": "本次计划会覆盖已有中间产物。",
                    "required": False,
                }
            )

        options = self._options_payload(request, inferred, tuple(spec.name for spec in selected))
        goal = request.task.strip() or "构建日志知识图谱"
        return PipelinePlan(
            goal=goal,
            nodes=nodes,
            options=options,
            warnings=warnings,
            confirmations=confirmations,
            decisions=decisions,
        )

    def options_from_plan(self, plan: PipelinePlan) -> AgentRunOptions:
        raw = plan.options
        return AgentRunOptions(
            dataset_names=tuple(raw.get("dataset_names", [])),
            force_template2samples=bool(raw.get("force_template2samples", False)),
            force_pairs=bool(raw.get("force_pairs", False)),
            force_schema=bool(raw.get("force_schema", False)),
            force_mapped_pairs=bool(raw.get("force_mapped_pairs", False)),
            force_params=bool(raw.get("force_params", False)),
            skip_llm_steps=bool(raw.get("skip_llm_steps", False)),
            skip_param_extraction=bool(raw.get("skip_param_extraction", False)),
            skip_kg_build=bool(raw.get("skip_kg_build", False)),
            api_key=str(raw.get("api_key", "")),
            limit_rows=raw.get("limit_rows"),
            per_dataset_graph_dir=PROJECT_ROOT / raw.get("per_dataset_graph_dir", str(GRAPH_SOURCES_DIR)),
            fused_graph_dir=PROJECT_ROOT / raw.get("fused_graph_dir", str(GRAPH_FUSED_DIR)),
            write_neo4j=bool(raw.get("write_neo4j", False)),
            neo4j_uri=str(raw.get("neo4j_uri", "")),
            neo4j_user=str(raw.get("neo4j_user", "")),
            neo4j_password=str(raw.get("neo4j_password", "")),
            neo4j_database=str(raw.get("neo4j_database", "neo4j")),
        )

    def _select_datasets(self, request: PlannerRequest) -> list[DatasetSpec]:
        requested = set(request.datasets) or set(self._infer_dataset_names(request.task))
        if not requested:
            return list(self.specs)
        by_name = {spec.name: spec for spec in self.specs}
        missing = sorted(requested - set(by_name))
        if missing:
            raise ValueError(f"Unknown dataset(s): {', '.join(missing)}")
        return [by_name[name] for name in sorted(requested)]

    def _infer_dataset_names(self, task: str) -> list[str]:
        text = task.lower()
        names = []
        for spec in self.specs:
            tokens = {spec.name.lower(), spec.family.lower()}
            if spec.family == "dns":
                tokens.update({"dnsmasq", "dns"})
            if spec.family == "vpn":
                tokens.update({"openvpn", "vpn"})
            if spec.family == "apache":
                tokens.update({"apache", "access" if "access" in spec.name else "error"})
            if any(token and token in text for token in tokens):
                names.append(spec.name)
        return names

    def _infer_options(self, request: PlannerRequest, preflight: PreflightReport) -> dict[str, Any]:
        task = request.task.lower()
        decisions: list[str] = []

        skip_llm = request.skip_llm_steps
        skip_params = request.skip_param_extraction
        skip_kg = request.skip_kg_build
        force = request.force or bool(re.search(r"强制|覆盖|重新生成|重跑|重新抽取|重新映射", task))
        all_pairs_schema_ready = self._all_artifacts_exist(preflight, ("pairs", "schema"))
        all_params_ready = self._all_artifacts_exist(preflight, ("params_csv",))

        if skip_llm is None:
            if re.search(r"跳过\s*(deepseek|llm)|不调用|现有|已有|快速", task):
                skip_llm = all_pairs_schema_ready and not force
                if not skip_llm:
                    decisions.append("任务倾向复用 LLM 产物，但 pairs/schema 不完整，agent 将补齐缺失步骤")
            else:
                skip_llm = all_pairs_schema_ready and not force
        if skip_params is None:
            if re.search(r"跳过.*参数|现有.*csv|已有.*csv|快速", task):
                skip_params = all_params_ready and not force
                if not skip_params:
                    decisions.append("任务倾向复用 params CSV，但参数文件不完整，agent 将补齐缺失步骤")
            else:
                skip_params = all_params_ready and not force
        if skip_kg is None:
            skip_kg = bool(re.search(r"只.*抽取|不要.*图|跳过.*图谱", task))

        if re.search(r"完整|全流程|重跑|重新", task):
            if request.skip_llm_steps is None:
                skip_llm = all_pairs_schema_ready and not force
            if request.skip_param_extraction is None:
                skip_params = all_params_ready and not force
            if request.skip_kg_build is None:
                skip_kg = False
            decisions.append("任务文本要求完整/重跑流程，agent 会结合现有产物决定是否复用")

        if all_pairs_schema_ready and skip_llm:
            decisions.append("所有所选数据集已有 pairs/schema，自动复用字段语义与 POI 映射产物")
        if all_params_ready and skip_params:
            decisions.append("所有所选数据集已有 params CSV，自动复用参数抽取产物")
        if force:
            decisions.append("任务要求重新生成或覆盖，已有中间产物不会作为跳过依据")

        write_neo4j = request.write_neo4j

        return {
            "force": bool(force),
            "skip_llm_steps": bool(skip_llm),
            "skip_param_extraction": bool(skip_params),
            "skip_kg_build": bool(skip_kg),
            "write_neo4j": bool(write_neo4j),
            "decisions": decisions,
        }

    def _options_payload(
        self,
        request: PlannerRequest,
        inferred: dict[str, Any],
        dataset_names: tuple[str, ...],
    ) -> dict[str, Any]:
        force = bool(inferred["force"])
        return {
            "dataset_names": list(dataset_names),
            "force_template2samples": force,
            "force_pairs": force,
            "force_schema": force,
            "force_mapped_pairs": force,
            "force_params": force,
            "skip_llm_steps": inferred["skip_llm_steps"],
            "skip_param_extraction": inferred["skip_param_extraction"],
            "skip_kg_build": inferred["skip_kg_build"],
            "api_key": request.api_key,
            "limit_rows": request.limit_rows,
            "per_dataset_graph_dir": request.per_dataset_graph_dir or str(GRAPH_SOURCES_DIR),
            "fused_graph_dir": request.fused_graph_dir or str(GRAPH_FUSED_DIR),
            "write_neo4j": inferred["write_neo4j"],
            "neo4j_uri": request.neo4j_uri,
            "neo4j_user": request.neo4j_user,
            "neo4j_password": request.neo4j_password,
            "neo4j_database": request.neo4j_database or "neo4j",
            "max_workers": max(1, int(request.max_workers or 1)),
        }

    @staticmethod
    def _node_id(dataset: str, step: str) -> str:
        return f"{dataset}__{step}"

    @staticmethod
    def _artifact_exists(artifacts: dict[str, Any], name: str) -> bool:
        status = artifacts.get(name)
        return bool(status and getattr(status, "exists", False))

    def _all_artifacts_exist(self, preflight: PreflightReport, names: tuple[str, ...]) -> bool:
        if not preflight.datasets:
            return False
        for dataset in preflight.datasets:
            if not all(self._artifact_exists(dataset.artifacts, name) for name in names):
                return False
        return True
