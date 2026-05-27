from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class PipelineNode:
    id: str
    tool: str
    dataset: str = "all"
    deps: tuple[str, ...] = ()
    reason: str = ""
    optional: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "dataset": self.dataset,
            "deps": list(self.deps),
            "reason": self.reason,
            "optional": self.optional,
        }


@dataclass
class PipelinePlan:
    goal: str
    nodes: list[PipelineNode]
    options: dict[str, Any]
    plan_id: str = field(default_factory=lambda: uuid4().hex[:12])
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    warnings: list[str] = field(default_factory=list)
    confirmations: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "goal": self.goal,
            "created_at": self.created_at,
            "nodes": [node.to_dict() for node in self.nodes],
            "options": self.options,
            "warnings": self.warnings,
            "confirmations": self.confirmations,
            "decisions": self.decisions,
        }

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    def topological_nodes(self) -> list[PipelineNode]:
        pending = {node.id: node for node in self.nodes}
        done: set[str] = set()
        ordered: list[PipelineNode] = []

        while pending:
            ready = [
                node
                for node in pending.values()
                if all(dep in done for dep in node.deps)
            ]
            if not ready:
                unresolved = ", ".join(sorted(pending))
                raise ValueError(f"Pipeline plan has unresolved dependency cycle: {unresolved}")
            for node in sorted(ready, key=lambda item: item.id):
                ordered.append(node)
                done.add(node.id)
                pending.pop(node.id)

        return ordered
