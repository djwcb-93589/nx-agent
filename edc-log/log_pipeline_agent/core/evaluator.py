from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd


@dataclass
class EvaluationFinding:
    severity: str
    target: str
    message: str
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "target": self.target,
            "message": self.message,
            "metrics": self.metrics,
        }


@dataclass
class EvaluationReport:
    findings: list[EvaluationFinding] = field(default_factory=list)

    def add(self, severity: str, target: str, message: str, **metrics: Any) -> None:
        self.findings.append(EvaluationFinding(severity, target, message, metrics))

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": {
                "error": sum(1 for finding in self.findings if finding.severity == "error"),
                "warning": sum(1 for finding in self.findings if finding.severity == "warning"),
                "info": sum(1 for finding in self.findings if finding.severity == "info"),
            },
        }


class ArtifactEvaluator:
    def evaluate_graph_dir(self, graph_dir: Path) -> EvaluationReport:
        report = EvaluationReport()
        nodes_path = graph_dir / "nodes.csv"
        edges_path = graph_dir / "edges.csv"

        if not nodes_path.exists():
            report.add("error", str(nodes_path), "缺少 nodes.csv")
            return report
        if not edges_path.exists():
            report.add("error", str(edges_path), "缺少 edges.csv")
            return report

        nodes = pd.read_csv(nodes_path, dtype=str, keep_default_na=False)
        edges = pd.read_csv(edges_path, dtype=str, keep_default_na=False)
        node_count = len(nodes)
        edge_count = len(edges)
        report.add("info", str(graph_dir), "图谱产物已生成", nodes=node_count, edges=edge_count)

        if node_count == 0:
            report.add("warning", str(nodes_path), "节点数为 0")
        if edge_count == 0:
            report.add("warning", str(edges_path), "边数为 0")

        node_ids = set(zip(nodes.get("label", []), nodes.get("id", [])))
        edge_endpoints = set(zip(edges.get("start_label", []), edges.get("start_id", [])))
        edge_endpoints.update(zip(edges.get("end_label", []), edges.get("end_id", [])))
        isolated = node_ids - edge_endpoints
        if node_count:
            isolated_ratio = len(isolated) / node_count
            if isolated_ratio > 0.3:
                report.add(
                    "warning",
                    str(nodes_path),
                    "孤立节点比例偏高",
                    isolated_nodes=len(isolated),
                    isolated_ratio=round(isolated_ratio, 4),
                )

        return report
