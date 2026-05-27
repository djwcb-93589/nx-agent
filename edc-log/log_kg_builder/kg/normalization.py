from __future__ import annotations

from typing import Any, Iterable

import pandas as pd

NULL_STRINGS = {"", "nan", "none", "null", "na", "n/a", "?", "unknown"}


def normalize_scalar(value: Any) -> str | None:
    """Convert raw values into normalized string scalars."""
    if value is None:
        return None
    if pd.isna(value):
        return None
    text = str(value).strip()
    if text.lower() in NULL_STRINGS:
        return None
    return text


def is_nullish(value: Any) -> bool:
    return normalize_scalar(value) is None


def normalize_user(value: Any) -> str | None:
    normalized = normalize_scalar(value)
    if normalized is None:
        return None
    return normalized.lower()


def normalize_domain(value: Any) -> str | None:
    normalized = normalize_scalar(value)
    if normalized is None:
        return None
    return normalized.lower()


def coalesce_row_values(row: dict[str, Any], fields: Iterable[str]) -> str | None:
    for field in fields:
        value = normalize_scalar(row.get(field))
        if value is not None:
            return value
    return None


def merge_non_empty_properties(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Keep existing values, but fill missing properties from incoming."""
    for key, value in incoming.items():
        if value is None:
            continue
        existing = target.get(key)
        if existing is None or (isinstance(existing, str) and existing.strip() == ""):
            target[key] = value

