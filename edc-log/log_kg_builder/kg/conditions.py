from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .normalization import is_nullish, normalize_scalar

AND_SPLIT_RE = re.compile(r"\s+AND\s+", re.IGNORECASE)
NOT_NULL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+not\s+null$", re.IGNORECASE)
IS_NULL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+is\s+null$", re.IGNORECASE)
NOT_INDICATES_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+not\s+indicates\s+(.+)$", re.IGNORECASE)
INDICATES_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+indicates\s+(.+)$", re.IGNORECASE)
NOT_EQUALS_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*(.+)$", re.IGNORECASE)
GREATER_EQUALS_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*>=\s*(.+)$", re.IGNORECASE)
LESS_EQUALS_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*<=\s*(.+)$", re.IGNORECASE)
GREATER_THAN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*>\s*(.+)$", re.IGNORECASE)
LESS_THAN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*<\s*(.+)$", re.IGNORECASE)
EQUALS_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|==)\s*(.+)$", re.IGNORECASE)
IN_LIST_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+in\s*\((.+)\)$", re.IGNORECASE)


@dataclass(frozen=True)
class ConditionClause:
    field: str
    operator: str
    value: str | None = None
    values: tuple[str, ...] | None = None

    def matches(self, row: dict[str, Any]) -> bool:
        raw_value = row.get(self.field)
        if self.operator == "not_null":
            return not is_nullish(raw_value)
        if self.operator == "is_null":
            return is_nullish(raw_value)
        if self.operator == "indicates":
            if is_nullish(raw_value):
                return False
            haystack = normalize_scalar(raw_value)
            needle = normalize_scalar(self.value)
            if haystack is None or needle is None:
                return False
            return needle.lower() in haystack.lower()
        if self.operator == "not_indicates":
            haystack = normalize_scalar(raw_value)
            needle = normalize_scalar(self.value)
            if haystack is None:
                return False
            if needle is None:
                return True
            return needle.lower() not in haystack.lower()
        if self.operator == "not_equals":
            lhs = normalize_scalar(raw_value)
            rhs = normalize_scalar(self.value)
            if lhs is None:
                return False
            if rhs is None:
                return True
            return lhs.lower() != rhs.lower()
        if self.operator in {"gt", "gte", "lt", "lte"}:
            lhs = normalize_scalar(raw_value)
            rhs = normalize_scalar(self.value)
            if lhs is None or rhs is None:
                return False
            return _compare_ordered(lhs, rhs, self.operator)
        if self.operator == "equals":
            lhs = normalize_scalar(raw_value)
            rhs = normalize_scalar(self.value)
            if lhs is None or rhs is None:
                return False
            return lhs.lower() == rhs.lower()
        if self.operator == "in":
            lhs = normalize_scalar(raw_value)
            if lhs is None or not self.values:
                return False
            lhs_norm = lhs.lower()
            return lhs_norm in {item.lower() for item in self.values}
        raise ValueError(f"Unsupported operator: {self.operator}")


@dataclass(frozen=True)
class CompiledCondition:
    expression: str
    clauses: list[ConditionClause]

    def matches(self, row: dict[str, Any]) -> bool:
        return all(clause.matches(row) for clause in self.clauses)


def parse_condition(expression: str | None) -> CompiledCondition:
    expr = (expression or "").strip()
    if not expr or expr.lower() in {"true", "always"}:
        return CompiledCondition(expression=expr, clauses=[])

    clauses: list[ConditionClause] = []
    parts = [token.strip() for token in AND_SPLIT_RE.split(expr) if token.strip()]
    for token in parts:
        match = NOT_NULL_RE.match(token)
        if match:
            clauses.append(ConditionClause(field=match.group(1), operator="not_null"))
            continue

        match = IS_NULL_RE.match(token)
        if match:
            clauses.append(ConditionClause(field=match.group(1), operator="is_null"))
            continue

        match = NOT_INDICATES_RE.match(token)
        if match:
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="not_indicates",
                    value=match.group(2).strip().strip("\"'"),
                )
            )
            continue

        match = INDICATES_RE.match(token)
        if match:
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="indicates",
                    value=match.group(2).strip().strip("\"'"),
                )
            )
            continue

        match = NOT_EQUALS_RE.match(token)
        if match:
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="not_equals",
                    value=match.group(2).strip().strip("\"'"),
                )
            )
            continue

        match = GREATER_EQUALS_RE.match(token)
        if match:
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="gte",
                    value=match.group(2).strip().strip("\"'"),
                )
            )
            continue

        match = LESS_EQUALS_RE.match(token)
        if match:
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="lte",
                    value=match.group(2).strip().strip("\"'"),
                )
            )
            continue

        match = GREATER_THAN_RE.match(token)
        if match:
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="gt",
                    value=match.group(2).strip().strip("\"'"),
                )
            )
            continue

        match = LESS_THAN_RE.match(token)
        if match:
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="lt",
                    value=match.group(2).strip().strip("\"'"),
                )
            )
            continue

        match = EQUALS_RE.match(token)
        if match:
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="equals",
                    value=match.group(2).strip().strip("\"'"),
                )
            )
            continue

        match = IN_LIST_RE.match(token)
        if match:
            raw_items = [item.strip().strip("\"'") for item in match.group(2).split(",")]
            items = tuple(item for item in raw_items if item)
            clauses.append(
                ConditionClause(
                    field=match.group(1),
                    operator="in",
                    values=items,
                )
            )
            continue

        raise ValueError(f"Unsupported condition clause: '{token}'")

    return CompiledCondition(expression=expr, clauses=clauses)


def _compare_ordered(lhs: str, rhs: str, operator: str) -> bool:
    try:
        lhs_num = float(lhs)
        rhs_num = float(rhs)
        if operator == "gt":
            return lhs_num > rhs_num
        if operator == "gte":
            return lhs_num >= rhs_num
        if operator == "lt":
            return lhs_num < rhs_num
        if operator == "lte":
            return lhs_num <= rhs_num
    except ValueError:
        pass

    lhs_text = lhs.casefold()
    rhs_text = rhs.casefold()
    if operator == "gt":
        return lhs_text > rhs_text
    if operator == "gte":
        return lhs_text >= rhs_text
    if operator == "lt":
        return lhs_text < rhs_text
    if operator == "lte":
        return lhs_text <= rhs_text
    raise ValueError(f"Unsupported ordered comparison operator: {operator}")
