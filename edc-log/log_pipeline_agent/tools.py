from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
import csv
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from typing import Any, Iterable

import pandas as pd

from map_pairs_with_schema import load_json, map_pairs_with_schema, save_json
from run import (
    TEMPLATE_SAMPLE_SEED,
    TEMPLATE_SAMPLE_SIZE,
    _build_template2samples_from_ait_df,
    _load_existing_template2samples,
)

from .config import PROJECT_ROOT, DatasetSpec
from env_utils import load_dotenv, resolve_env_value


_EDC_LEGACY_IO_LOCK = threading.Lock()


@dataclass
class ToolResult:
    tool: str
    message: str
    outputs: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    skipped: bool = False


@contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _path_text(path: Path) -> str:
    return str(path.resolve())


def _legacy_pairs_path(spec: DatasetSpec) -> Path:
    return PROJECT_ROOT / f"pairs_{spec.tag}.json"


def _legacy_schema_path(spec: DatasetSpec) -> Path:
    return PROJECT_ROOT / f"schema_{spec.tag}.json"


def _legacy_mapped_pairs_path(spec: DatasetSpec) -> Path:
    return PROJECT_ROOT / f"pairs_{spec.tag}_mapped.json"


def _legacy_params_path(spec: DatasetSpec) -> Path:
    return PROJECT_ROOT / "output" / spec.params_output_path.name


def _save_json_artifact(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    save_json(path, payload)


def _count_csv_rows(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)
        try:
            next(reader)
        except StopIteration:
            return 0
        return sum(1 for _ in reader)


def generate_template2samples(
    specs: Iterable[DatasetSpec],
    *,
    force: bool = False,
    sample_size: int = TEMPLATE_SAMPLE_SIZE,
    seed: int = TEMPLATE_SAMPLE_SEED,
) -> list[ToolResult]:
    results: list[ToolResult] = []

    for spec in specs:
        json_path = spec.template2samples_path
        if json_path.exists() and not force:
            cached = _load_existing_template2samples(json_path)
            if cached is not None:
                results.append(
                    ToolResult(
                        tool="generate_template2samples",
                        message=f"Loaded existing template2samples for {spec.name}",
                        outputs={"template2samples": _path_text(json_path)},
                        metrics={"templates": len(cached[0]), "event_ids": len(cached[1])},
                        skipped=True,
                    )
                )
                continue

        df = pd.read_csv(spec.csv_path)
        template2samples = _build_template2samples_from_ait_df(
            df,
            spec.csv_path,
            k=sample_size,
            seed=seed,
        )
        if template2samples is None:
            raise ValueError(f"Cannot build template2samples from {spec.csv_path}")

        json_path.parent.mkdir(parents=True, exist_ok=True)
        with json_path.open("w", encoding="utf-8") as file:
            json.dump(template2samples, file, ensure_ascii=False, indent=4)
            file.write("\n")

        results.append(
            ToolResult(
                tool="generate_template2samples",
                message=f"Generated template2samples for {spec.name}",
                outputs={"template2samples": _path_text(json_path)},
                metrics={"templates": len(template2samples[0]), "event_ids": len(template2samples[1])},
            )
        )

    return results


def _load_template2samples(path: Path) -> list[list[str]]:
    data = _load_existing_template2samples(path)
    if data is None:
        raise ValueError(f"Invalid template2samples JSON: {path}")
    return data


def _build_edc_config(
    spec: DatasetSpec,
    *,
    output_dir: Path,
    oie_model: str = "deepseek-chat",
    schema_model: str = "deepseek-chat",
    canonicalization_model: str = "deepseek-chat",
) -> dict[str, Any]:
    return {
        "oie_llm": oie_model,
        "oie_prompt_template_file_path": str(PROJECT_ROOT / "prompt_templates" / "oie_template.txt"),
        "oie_few_shot_example_file_path": str(
            PROJECT_ROOT / "few_shot_examples" / "example" / "oie_few_shot_examples.txt"
        ),
        "sd_llm": schema_model,
        "sd_prompt_template_file_path": str(PROJECT_ROOT / "prompt_templates" / "sd_template.txt"),
        "sd_few_shot_example_file_path": str(
            PROJECT_ROOT / "few_shot_examples" / "example" / "sd_few_shot_examples.txt"
        ),
        "sc_llm": canonicalization_model,
        "sc_prompt_template_file_path": str(PROJECT_ROOT / "prompt_templates" / "sc_template_deepseek_mapping.txt"),
        "oie_refine_prompt_template_file_path": str(PROJECT_ROOT / "prompt_templates" / "oie_r_template.txt"),
        "oie_refine_few_shot_example_file_path": str(
            PROJECT_ROOT / "few_shot_examples" / "example" / "oie_few_shot_refine_examples.txt"
        ),
        "ee_llm": "deepseek-chat",
        "ee_prompt_template_file_path": str(PROJECT_ROOT / "prompt_templates" / "ee_template.txt"),
        "ee_few_shot_example_file_path": str(
            PROJECT_ROOT / "few_shot_examples" / "example" / "ee_few_shot_examples.txt"
        ),
        "em_prompt_template_file_path": str(PROJECT_ROOT / "prompt_templates" / "em_template.txt"),
        "input_text_file_path": "",
        "target_schema_path": str(spec.poi_schema_path),
        "refinement_iterations": 0,
        "enrich_schema": False,
        "output_dir": str(output_dir),
        "loglevel": logging.INFO,
    }


def extract_field_semantics(
    spec: DatasetSpec,
    *,
    force: bool = False,
    api_key: str = "",
    output_dir: Path | None = None,
) -> ToolResult:
    load_dotenv(PROJECT_ROOT)
    if spec.pairs_path.exists() and not force:
        pairs = load_json(spec.pairs_path)
        return ToolResult(
            tool="extract_field_semantics",
            message=f"Loaded existing pairs JSON for {spec.name}",
            outputs={"pairs": _path_text(spec.pairs_path)},
            metrics={"templates": len(pairs) if isinstance(pairs, list) else 0},
            skipped=True,
        )
    legacy_path = _legacy_pairs_path(spec)
    if legacy_path.exists() and not force:
        pairs = load_json(legacy_path)
        _save_json_artifact(spec.pairs_path, pairs)
        return ToolResult(
            tool="extract_field_semantics",
            message=f"Imported existing pairs JSON for {spec.name} into artifacts",
            outputs={"pairs": _path_text(spec.pairs_path)},
            metrics={"templates": len(pairs) if isinstance(pairs, list) else 0},
            skipped=True,
        )

    api_key = str(resolve_env_value(api_key) or "")
    if api_key:
        os.environ["DS_TOKEN"] = api_key
        os.environ["DEEPSEEK_API_KEY"] = api_key

    template2samples = _load_template2samples(spec.template2samples_path)
    output_dir = output_dir or (PROJECT_ROOT / "log_output")

    with _EDC_LEGACY_IO_LOCK:
        with working_directory(PROJECT_ROOT):
            from edc.edc_framework import EDC

            edc = EDC(**_build_edc_config(spec, output_dir=output_dir))
            edc.oie(template2samples[0], type=spec.tag)

    source_path = legacy_path if force and legacy_path.exists() else (
        spec.pairs_path if spec.pairs_path.exists() else legacy_path
    )
    pairs = load_json(source_path)
    if source_path != spec.pairs_path:
        _save_json_artifact(spec.pairs_path, pairs)
    return ToolResult(
        tool="extract_field_semantics",
        message=f"Extracted field semantics for {spec.name}",
        outputs={"pairs": _path_text(spec.pairs_path)},
        metrics={"templates": len(pairs) if isinstance(pairs, list) else 0},
    )


def map_fields_to_poi_schema(
    spec: DatasetSpec,
    *,
    force: bool = False,
    api_key: str = "",
    output_dir: Path | None = None,
) -> ToolResult:
    load_dotenv(PROJECT_ROOT)
    if spec.schema_path.exists() and not force:
        schema = load_json(spec.schema_path)
        return ToolResult(
            tool="map_fields_to_poi_schema",
            message=f"Loaded existing schema mapping for {spec.name}",
            outputs={"schema": _path_text(spec.schema_path)},
            metrics={"templates": len(schema) if isinstance(schema, list) else 0},
            skipped=True,
        )
    legacy_path = _legacy_schema_path(spec)
    if legacy_path.exists() and not force:
        schema = load_json(legacy_path)
        _save_json_artifact(spec.schema_path, schema)
        return ToolResult(
            tool="map_fields_to_poi_schema",
            message=f"Imported existing schema mapping for {spec.name} into artifacts",
            outputs={"schema": _path_text(spec.schema_path)},
            metrics={"templates": len(schema) if isinstance(schema, list) else 0},
            skipped=True,
        )

    api_key = str(resolve_env_value(api_key) or "")
    if api_key:
        os.environ["DS_TOKEN"] = api_key
        os.environ["DEEPSEEK_API_KEY"] = api_key

    template2samples = _load_template2samples(spec.template2samples_path)
    pairs = load_json(spec.pairs_path)
    output_dir = output_dir or (PROJECT_ROOT / "log_output")

    with _EDC_LEGACY_IO_LOCK:
        with working_directory(PROJECT_ROOT):
            from edc.edc_framework import EDC

            edc = EDC(**_build_edc_config(spec, output_dir=output_dir))
            canonicalized, candidate_dicts = edc.schema_canonicalization(template2samples[0], pairs)
            if not candidate_dicts:
                raise ValueError(f"No schema candidates returned for {spec.name}")
            general_keys = list(candidate_dicts[0].keys())
            edc.split_mappings_keep_other_keys(canonicalized, general_keys, spec.tag)

    source_path = legacy_path if force and legacy_path.exists() else (
        spec.schema_path if spec.schema_path.exists() else legacy_path
    )
    schema = load_json(source_path)
    if source_path != spec.schema_path:
        _save_json_artifact(spec.schema_path, schema)
    return ToolResult(
        tool="map_fields_to_poi_schema",
        message=f"Mapped fields to POI schema for {spec.name}",
        outputs={"schema": _path_text(spec.schema_path)},
        metrics={"templates": len(schema) if isinstance(schema, list) else 0},
    )


def merge_pairs_with_schema_mapping(spec: DatasetSpec, *, force: bool = False) -> ToolResult:
    if spec.mapped_pairs_path.exists() and not force:
        mapped = load_json(spec.mapped_pairs_path)
        return ToolResult(
            tool="merge_pairs_with_schema_mapping",
            message=f"Loaded existing mapped pairs JSON for {spec.name}",
            outputs={"mapped_pairs": _path_text(spec.mapped_pairs_path)},
            metrics={"templates": len(mapped) if isinstance(mapped, list) else 0},
            skipped=True,
        )
    legacy_path = _legacy_mapped_pairs_path(spec)
    if legacy_path.exists() and not force:
        mapped = load_json(legacy_path)
        _save_json_artifact(spec.mapped_pairs_path, mapped)
        return ToolResult(
            tool="merge_pairs_with_schema_mapping",
            message=f"Imported existing mapped pairs JSON for {spec.name} into artifacts",
            outputs={"mapped_pairs": _path_text(spec.mapped_pairs_path)},
            metrics={"templates": len(mapped) if isinstance(mapped, list) else 0},
            skipped=True,
        )

    pairs = load_json(spec.pairs_path)
    schema = load_json(spec.schema_path)
    if not isinstance(pairs, list):
        raise TypeError(f"Pairs JSON must be a list: {spec.pairs_path}")
    if not isinstance(schema, list):
        raise TypeError(f"Schema JSON must be a list: {spec.schema_path}")

    mapped_pairs = map_pairs_with_schema(pairs, schema)
    _save_json_artifact(spec.mapped_pairs_path, mapped_pairs)
    return ToolResult(
        tool="merge_pairs_with_schema_mapping",
        message=f"Merged pairs and schema mapping for {spec.name}",
        outputs={"mapped_pairs": _path_text(spec.mapped_pairs_path)},
        metrics={"templates": len(mapped_pairs)},
    )


def extract_params_from_logs(
    spec: DatasetSpec,
    *,
    force: bool = False,
    api_key: str = "",
) -> ToolResult:
    load_dotenv(PROJECT_ROOT)
    if spec.params_output_path.exists() and not force:
        return ToolResult(
            tool="extract_params_from_logs",
            message=f"Loaded existing params CSV for {spec.name}",
            outputs={"params_csv": _path_text(spec.params_output_path)},
            metrics={"rows": _count_csv_rows(spec.params_output_path)},
            skipped=True,
        )
    legacy_path = _legacy_params_path(spec)
    if legacy_path.exists() and not force:
        spec.params_output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(legacy_path, spec.params_output_path)
        return ToolResult(
            tool="extract_params_from_logs",
            message=f"Imported existing params CSV for {spec.name} into artifacts",
            outputs={"params_csv": _path_text(spec.params_output_path)},
            metrics={"rows": _count_csv_rows(spec.params_output_path)},
            skipped=True,
        )

    api_key = str(resolve_env_value(api_key) or "")
    if api_key:
        os.environ["DS_TOKEN"] = api_key
        os.environ["DEEPSEEK_API_KEY"] = api_key

    spec.params_output_path.parent.mkdir(parents=True, exist_ok=True)
    if force and spec.params_output_path.exists():
        if spec.params_output_path.is_dir():
            raise IsADirectoryError(f"Params output path is a directory: {spec.params_output_path}")
        spec.params_output_path.unlink()
    command = [
        sys.executable,
        str(spec.extractor_script_path),
        "--input-csv",
        str(spec.csv_path),
        "--pairs-json",
        str(spec.mapped_pairs_path),
        "--output-csv",
        str(spec.params_output_path),
        "--log-source",
        spec.log_source,
        *spec.extractor_extra_args,
    ]
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Param extraction failed for {spec.name} with exit code {completed.returncode}\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )

    return ToolResult(
        tool="extract_params_from_logs",
        message=f"Extracted params CSV for {spec.name}",
        outputs={"params_csv": _path_text(spec.params_output_path)},
        metrics={"rows": _count_csv_rows(spec.params_output_path)},
    )


def build_graph_for_dataset(
    spec: DatasetSpec,
    *,
    output_dir: Path | None = None,
    limit_rows: int | None = None,
) -> tuple[ToolResult, Any]:
    from log_kg_builder.kg.graph_builder import GraphBuilder
    from log_kg_builder.kg.rules import load_relation_rules

    rules = load_relation_rules(spec.relation_csv_path)
    params_df = pd.read_csv(spec.params_output_path, dtype=str, keep_default_na=False)
    if limit_rows is not None:
        params_df = params_df.head(limit_rows).copy()

    result = GraphBuilder(rules=rules).build(params_df)
    if output_dir is not None:
        dump_graph_artifacts(output_dir, result)

    tool_result = ToolResult(
        tool="build_graph_for_dataset",
        message=f"Built graph for {spec.name}",
        outputs={"graph_dir": _path_text(output_dir)} if output_dir is not None else {},
        metrics={
            "input_rows": result.row_count,
            "unique_nodes": len(result.nodes),
            "unique_edges": len(result.edges),
            "rules": len(rules),
        },
    )
    return tool_result, result


def dump_graph_artifacts(output_dir: Path, result: Any) -> None:
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


def fuse_graph_results(named_results: Iterable[tuple[str, Any]]) -> Any:
    from log_kg_builder.kg.graph_builder import BuildResult, EdgeRecord, NodeRecord
    from log_kg_builder.kg.normalization import merge_non_empty_properties

    node_index: dict[tuple[str, str], NodeRecord] = {}
    edge_index: dict[tuple[str, str, str, str, str], EdgeRecord] = {}
    rule_hits: Counter = Counter()
    row_count = 0

    for source_name, result in named_results:
        row_count += result.row_count
        rule_hits.update({f"{source_name}:{rule_id}": hits for rule_id, hits in result.rule_hit_counter.items()})

        for node in result.nodes:
            key = (node.label, node.node_id)
            existing = node_index.get(key)
            props = dict(node.properties)
            props.setdefault("sources", [])
            if isinstance(props["sources"], list) and source_name not in props["sources"]:
                props["sources"].append(source_name)
            if existing is None:
                node_index[key] = NodeRecord(label=node.label, node_id=node.node_id, properties=props)
            else:
                merge_non_empty_properties(existing.properties, props)
                sources = existing.properties.setdefault("sources", [])
                if isinstance(sources, list) and source_name not in sources:
                    sources.append(source_name)

        for edge in result.edges:
            key = (edge.start_label, edge.start_id, edge.predicate, edge.end_label, edge.end_id)
            existing = edge_index.get(key)
            props = dict(edge.properties)
            props.setdefault("sources", [])
            if isinstance(props["sources"], list) and source_name not in props["sources"]:
                props["sources"].append(source_name)
            if existing is None:
                edge_index[key] = EdgeRecord(
                    start_label=edge.start_label,
                    start_id=edge.start_id,
                    predicate=edge.predicate,
                    end_label=edge.end_label,
                    end_id=edge.end_id,
                    properties=props,
                )
            else:
                merge_non_empty_properties(existing.properties, props)
                sources = existing.properties.setdefault("sources", [])
                if isinstance(sources, list) and source_name not in sources:
                    sources.append(source_name)

    return BuildResult(
        nodes=list(node_index.values()),
        edges=list(edge_index.values()),
        rule_hit_counter=rule_hits,
        row_count=row_count,
    )


def write_graph_to_neo4j(
    graph_result: Any,
    *,
    uri: str,
    user: str,
    password: str,
    database: str = "neo4j",
    batch_size: int = 1000,
    create_constraints: bool = True,
) -> ToolResult:
    from log_kg_builder.kg.neo4j_writer import Neo4jConfig, Neo4jWriter

    config = Neo4jConfig(
        uri=uri,
        user=user,
        password=password,
        database=database,
        batch_size=batch_size,
        create_constraints=create_constraints,
    )
    with Neo4jWriter(config) as writer:
        if create_constraints:
            writer.create_unique_constraints(graph_result.node_labels)
        writer.write_graph(graph_result.nodes, graph_result.edges)

    return ToolResult(
        tool="write_graph_to_neo4j",
        message="Wrote fused graph to Neo4j",
        metrics={"nodes": len(graph_result.nodes), "edges": len(graph_result.edges)},
    )


def query_neo4j_graph(
    *,
    config_path: Path,
    question: str,
    refresh_schema: bool = False,
    max_result_rows: int | None = None,
    max_answer_rows: int | None = None,
) -> ToolResult:
    from log_kg_query_agent.query_agent.config import load_query_agent_config
    from log_kg_query_agent.query_agent.engine import QueryAgent

    config = load_query_agent_config(config_path)
    agent = QueryAgent(config).with_runtime_overrides(
        max_result_rows=max_result_rows,
        max_answer_rows=max_answer_rows,
    )
    answer = agent.run(question, refresh_schema=refresh_schema)

    return ToolResult(
        tool="query_neo4j_graph",
        message=answer.answer,
        outputs={"schema_cache": _path_text(agent.config.runtime.schema_cache_path)},
        metrics={"rows": len(answer.rows), "truncated": answer.truncated, "cypher": answer.plan.cypher},
    )


def query_graph_artifacts(
    *,
    graph_dir: Path,
    label: str = "",
    predicate: str = "",
    contains: str = "",
    limit: int = 20,
) -> ToolResult:
    rows: list[dict[str, Any]] = []
    needle = contains.casefold().strip()

    nodes_path = graph_dir / "nodes.csv"
    edges_path = graph_dir / "edges.csv"

    if label and nodes_path.exists():
        df = pd.read_csv(nodes_path, dtype=str, keep_default_na=False)
        subset = df[df["label"].str.casefold() == label.casefold()]
        if needle:
            subset = subset[
                subset.apply(lambda row: needle in json.dumps(row.to_dict(), ensure_ascii=False).casefold(), axis=1)
            ]
        rows.extend(subset.head(limit).to_dict(orient="records"))

    if predicate and edges_path.exists():
        df = pd.read_csv(edges_path, dtype=str, keep_default_na=False)
        subset = df[df["predicate"].str.casefold() == predicate.casefold()]
        if needle:
            subset = subset[
                subset.apply(lambda row: needle in json.dumps(row.to_dict(), ensure_ascii=False).casefold(), axis=1)
            ]
        rows.extend(subset.head(limit).to_dict(orient="records"))

    if not label and not predicate:
        for path in (nodes_path, edges_path):
            if not path.exists():
                continue
            df = pd.read_csv(path, dtype=str, keep_default_na=False)
            if needle:
                df = df[df.apply(lambda row: needle in json.dumps(row.to_dict(), ensure_ascii=False).casefold(), axis=1)]
            rows.extend(df.head(max(0, limit - len(rows))).to_dict(orient="records"))
            if len(rows) >= limit:
                break

    return ToolResult(
        tool="query_graph_artifacts",
        message=json.dumps(rows[:limit], ensure_ascii=False, indent=2),
        outputs={"graph_dir": _path_text(graph_dir)},
        metrics={"rows": len(rows[:limit])},
    )
