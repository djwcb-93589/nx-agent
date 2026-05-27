from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from .conditions import CompiledCondition, parse_condition

REQUIRED_RULE_COLUMNS = {
    "subject_type",
    "subject_id_source",
    "predicate",
    "object_type",
    "object_id_source",
    "edge_properties",
    "condition",
}


def _parse_csv_list(raw_value: str | None) -> list[str]:
    if raw_value is None:
        return []
    return [item.strip() for item in str(raw_value).split(",") if item.strip()]


@dataclass(frozen=True)
class RelationRule:
    rule_id: str
    subject_type: str
    subject_id_source: str
    predicate: str
    object_type: str
    object_id_source: str
    edge_property_fields: list[str]
    condition_expression: str
    condition: CompiledCondition

    def matches(self, row: dict[str, Any]) -> bool:
        return self.condition.matches(row)


def load_relation_rules(csv_path: str | Path) -> list[RelationRule]:
    path = Path(csv_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Relation CSV not found: {path}")

    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    missing = REQUIRED_RULE_COLUMNS - set(df.columns)
    if missing:
        missing_columns = ", ".join(sorted(missing))
        raise ValueError(f"Missing required columns in relation CSV: {missing_columns}")

    rules: list[RelationRule] = []
    for idx, row in df.iterrows():
        condition_expr = str(row.get("condition", "")).strip()
        condition = parse_condition(condition_expr)
        rules.append(
            RelationRule(
                rule_id=f"R{idx + 1}",
                subject_type=str(row["subject_type"]).strip(),
                subject_id_source=str(row["subject_id_source"]).strip(),
                predicate=str(row["predicate"]).strip(),
                object_type=str(row["object_type"]).strip(),
                object_id_source=str(row["object_id_source"]).strip(),
                edge_property_fields=_parse_csv_list(row.get("edge_properties", "")),
                condition_expression=condition_expr,
                condition=condition,
            )
        )
    return rules

