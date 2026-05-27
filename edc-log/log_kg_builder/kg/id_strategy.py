from __future__ import annotations

import re
from typing import Any

from .normalization import normalize_domain, normalize_scalar, normalize_user


INTEGER_LIKE_FLOAT_RE = re.compile(r"^[+-]?\d+\.0+$")


def _canonicalize_integer_like(value: str | None) -> str | None:
    if value is None:
        return None
    if INTEGER_LIKE_FLOAT_RE.match(value):
        return value.split(".", 1)[0]
    return value


def build_node_id(node_type: str, id_source: str, row: dict[str, Any]) -> str | None:
    base_value = normalize_scalar(row.get(id_source))
    if base_value is None:
        return None

    if node_type == "Process":
        base_value = _canonicalize_integer_like(base_value)
        host = normalize_scalar(row.get("host")) or ""
        return f"{host}|{base_value}"

    if node_type == "Interface":
        base_value = _canonicalize_integer_like(base_value)
        host = normalize_scalar(row.get("host")) or ""
        return f"{host}|{base_value}"

    if node_type == "User":
        return normalize_user(base_value)

    if node_type == "Domain":
        return normalize_domain(base_value)

    if node_type == "Session":
        return _canonicalize_integer_like(base_value)

    return base_value


def build_node_properties(
    node_type: str,
    node_id: str,
    id_source: str,
    row: dict[str, Any],
) -> dict[str, Any]:
    props: dict[str, Any] = {}

    raw_value = normalize_scalar(row.get(id_source))
    if node_type == "Process":
        raw_value = _canonicalize_integer_like(raw_value)
        props["process"] = node_id
        props["pid"] = raw_value
        host = normalize_scalar(row.get("host"))
        if host is not None:
            props["host"] = host
        return props

    if node_type == "Interface":
        props["interface"] = node_id
        props["iface"] = raw_value
        host = normalize_scalar(row.get("host"))
        if host is not None:
            props["host"] = host
        return props

    if node_type == "Host":
        props["host"] = node_id
    elif node_type == "Program":
        props["program"] = node_id
    elif node_type == "User":
        props["user"] = node_id
    elif node_type == "IP":
        props["ip"] = node_id
    elif node_type == "Command":
        props["command"] = node_id
    elif node_type == "Object":
        props["object_name"] = node_id
    elif node_type == "Domain":
        props["qname"] = node_id
    elif node_type == "Session":
        props["session_id"] = node_id
    elif node_type == "Terminal":
        props["terminal"] = node_id
    elif node_type == "Syscall":
        props["syscall"] = node_id
    else:
        if raw_value is not None:
            props[id_source] = raw_value

    return props
