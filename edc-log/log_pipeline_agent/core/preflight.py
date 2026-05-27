from __future__ import annotations

from dataclasses import dataclass, field
import csv
import json
from pathlib import Path
from typing import Any

from ..config import DatasetSpec, discover_dataset_specs


@dataclass
class ArtifactStatus:
    path: str
    exists: bool
    kind: str
    metrics: dict[str, Any] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "kind": self.kind,
            "metrics": self.metrics,
            "issues": self.issues,
        }


@dataclass
class DatasetPreflight:
    name: str
    family: str
    tag: str
    artifacts: dict[str, ArtifactStatus]
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "family": self.family,
            "tag": self.tag,
            "artifacts": {name: status.to_dict() for name, status in self.artifacts.items()},
            "issues": self.issues,
            "warnings": self.warnings,
            "recommendations": self.recommendations,
        }


@dataclass
class PreflightReport:
    datasets: list[DatasetPreflight]
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "datasets": [dataset.to_dict() for dataset in self.datasets],
            "issues": self.issues,
            "warnings": self.warnings,
            "recommendations": self.recommendations,
        }


class PreflightAnalyzer:
    def __init__(self, specs: list[DatasetSpec] | None = None) -> None:
        self.specs = specs if specs is not None else discover_dataset_specs()

    def run(self, dataset_names: tuple[str, ...] = ()) -> PreflightReport:
        selected = self._select(dataset_names)
        dataset_reports = [self._analyze_dataset(spec) for spec in selected]
        issues = [f"{item.name}: {issue}" for item in dataset_reports for issue in item.issues]
        warnings = [f"{item.name}: {warning}" for item in dataset_reports for warning in item.warnings]

        recommendations: list[str] = []
        for item in dataset_reports:
            recommendations.extend(f"{item.name}: {rec}" for rec in item.recommendations)
        if not dataset_reports:
            issues.append("没有找到可处理的数据集")

        return PreflightReport(
            datasets=dataset_reports,
            issues=issues,
            warnings=warnings,
            recommendations=recommendations,
        )

    def _select(self, dataset_names: tuple[str, ...]) -> list[DatasetSpec]:
        if not dataset_names:
            return list(self.specs)
        by_name = {spec.name: spec for spec in self.specs}
        missing = sorted(set(dataset_names) - set(by_name))
        if missing:
            raise ValueError(f"Unknown dataset(s): {', '.join(missing)}")
        return [by_name[name] for name in dataset_names]

    def _analyze_dataset(self, spec: DatasetSpec) -> DatasetPreflight:
        artifacts = {
            "source_csv": self._csv_status(spec.csv_path),
            "template2samples": self._json_status(spec.template2samples_path),
            "pairs": self._json_status(spec.pairs_path),
            "schema": self._json_status(spec.schema_path),
            "mapped_pairs": self._json_status(spec.mapped_pairs_path),
            "params_csv": self._csv_status(spec.params_output_path),
            "relation_csv": self._csv_status(spec.relation_csv_path),
            "poi_schema": self._csv_status(spec.poi_schema_path),
        }
        issues: list[str] = []
        warnings: list[str] = []
        recommendations: list[str] = []

        for key, status in artifacts.items():
            if not status.exists:
                issues.append(f"缺少 {key}: {status.path}")

        source_rows = artifacts["source_csv"].metrics.get("rows")
        param_rows = artifacts["params_csv"].metrics.get("rows")
        if source_rows is not None and param_rows is not None and source_rows != param_rows:
            warnings.append(f"params CSV 行数 {param_rows} 与原始日志行数 {source_rows} 不一致")
            recommendations.append("建议重跑或 resume 参数抽取")

        pairs_len = artifacts["pairs"].metrics.get("top_level_items")
        schema_len = artifacts["schema"].metrics.get("top_level_items")
        mapped_len = artifacts["mapped_pairs"].metrics.get("top_level_items")
        if pairs_len is not None and schema_len is not None and pairs_len != schema_len:
            warnings.append(f"pairs 数量 {pairs_len} 与 schema 数量 {schema_len} 不一致")
            recommendations.append("建议重跑 POI 映射")
        if pairs_len is not None and mapped_len is not None and pairs_len != mapped_len:
            warnings.append(f"pairs 数量 {pairs_len} 与 mapped 数量 {mapped_len} 不一致")
            recommendations.append("建议重新合并 mapped JSON")

        coverage = self._relation_field_coverage(spec.relation_csv_path, spec.params_output_path)
        if coverage:
            artifacts["relation_coverage"] = ArtifactStatus(
                path=f"{spec.relation_csv_path} -> {spec.params_output_path}",
                exists=True,
                kind="derived",
                metrics=coverage,
            )
            missing_fields = coverage.get("missing_fields", [])
            if missing_fields:
                warnings.append(f"relation.csv 引用了 params CSV 中不存在的字段: {', '.join(missing_fields[:12])}")
                recommendations.append("建议检查 params 抽取列或 relation 规则")

        return DatasetPreflight(
            name=spec.name,
            family=spec.family,
            tag=spec.tag,
            artifacts=artifacts,
            issues=issues,
            warnings=warnings,
            recommendations=recommendations,
        )

    def _json_status(self, path: Path) -> ArtifactStatus:
        exists = path.exists()
        metrics: dict[str, Any] = {}
        issues: list[str] = []
        if exists:
            try:
                with path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
                metrics["top_level_type"] = type(data).__name__
                if isinstance(data, list):
                    metrics["top_level_items"] = len(data)
                elif isinstance(data, dict):
                    metrics["top_level_items"] = len(data)
            except Exception as exc:
                issues.append(f"JSON 解析失败: {exc}")
        return ArtifactStatus(str(path), exists, "json", metrics, issues)

    def _csv_status(self, path: Path) -> ArtifactStatus:
        exists = path.exists()
        metrics: dict[str, Any] = {}
        issues: list[str] = []
        if exists:
            try:
                with path.open("r", encoding="utf-8-sig", newline="") as file:
                    reader = csv.DictReader(file)
                    fieldnames = reader.fieldnames or []
                    metrics["columns"] = fieldnames
                    metrics["column_count"] = len(fieldnames)
                    metrics["rows"] = sum(1 for _ in reader)
            except Exception as exc:
                issues.append(f"CSV 解析失败: {exc}")
        return ArtifactStatus(str(path), exists, "csv", metrics, issues)

    def _relation_field_coverage(self, relation_csv: Path, params_csv: Path) -> dict[str, Any]:
        if not relation_csv.exists() or not params_csv.exists():
            return {}

        with params_csv.open("r", encoding="utf-8-sig", newline="") as file:
            params_reader = csv.DictReader(file)
            params_fields = set(params_reader.fieldnames or [])

        referenced: set[str] = set()
        with relation_csv.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                for column in ("subject_id_source", "object_id_source"):
                    value = row.get(column, "").strip()
                    if value:
                        referenced.add(value)
                for value in str(row.get("edge_properties", "")).split(","):
                    value = value.strip()
                    if value:
                        referenced.add(value)
                condition = row.get("condition", "")
                if condition.strip():
                    try:
                        from log_kg_builder.kg.conditions import parse_condition

                        compiled = parse_condition(condition)
                        for clause in compiled.clauses:
                            referenced.add(clause.field)
                    except Exception:
                        pass

        missing = sorted(referenced - params_fields)
        present = sorted(referenced & params_fields)
        return {
            "referenced_field_count": len(referenced),
            "present_field_count": len(present),
            "missing_field_count": len(missing),
            "missing_fields": missing,
            "coverage": round(len(present) / len(referenced), 4) if referenced else 1.0,
        }
