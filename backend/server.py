from __future__ import annotations

from datetime import datetime
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import threading

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_ROOT = Path(__file__).resolve().parent
for _path in (REPO_ROOT, BACKEND_ROOT):
    _path_text = str(_path)
    if _path_text not in sys.path:
        sys.path.insert(0, _path_text)

try:
    from . import extra_api
except ImportError:  # pragma: no cover - supports `python backend/server.py`.
    import extra_api

from env_utils import load_dotenv


EDC_ROOT = REPO_ROOT / "edc-log"
EDC_AIT_ROOT = EDC_ROOT / "AIT"
MAX_RUN_LOG_LINES = 2000
DEFAULT_GLM_BASE_URL = "https://open.bigmodel.cn/api/coding/paas/v4/"
LLM_SECRET_ENV_KEYS = (
    "ZAI_API_KEY",
    "GLM_API_KEY",
    "DEEPSEEK_API_KEY",
    "DS_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_KEY",
)
CUSTOMER_ACTION_TO_POI = {
    "添加": "add",
    "修改": "set",
    "编辑": "set",
    "删除": "del",
    "显示": "show",
    "清空": "clear",
    "恢复": "startup",
    "批量加载": "bulk_load",
    "登录": "login",
    "退出": "logout",
    "离开": "leave",
}
CUSTOMER_POLICY_TO_POI = {
    "允许": "permit",
    "禁止": "deny",
    "代理": "proxy",
}
CUSTOMER_EVENT_POI_ALIASES = {
    "time": ("login_time",),
    "device_name": ("control_name",),
    "user": ("login_account",),
    "management_ip": ("src_ip", "control_ip"),
    "src_addr": ("src_ip",),
    "dst_addr": ("dst_ip", "control_ip"),
    "service": ("protocol", "dst_port"),
    "policy_type": ("policy", "pcpolicy"),
}

SCHEMA_FAMILY_MARKERS = (
    ("apache", ("apache", "httpd", "tomcat")),
    ("openvpn", ("openvpn", "vpn")),
    ("dns", ("dnsmasq", "dns")),
    ("firewall", ("firewall", "firewallexamplae", "firewallexample", "防火墙")),
    ("auth", ("auth.log", "/auth", "\\auth", "sshd", "sudo")),
    ("audit", ("audit", "审计", "主审")),
    (
        "syslog",
        (
            "syslog",
            "messages",
            "kern.log",
            "检测器",
            "防病毒",
            "入侵检测",
            "应用系统",
            "终端",
            "套件",
            "邮件",
            "oa",
        ),
    ),
)

load_dotenv(REPO_ROOT)
for _secret_key in LLM_SECRET_ENV_KEYS:
    os.environ.pop(_secret_key, None)


try:
    from agent.defaults import DEFAULT_LLM_MODEL_ID
    from agent.trace import TRACE_PREFIX
except ImportError:
    DEFAULT_LLM_MODEL_ID = "glm-5.2"
    TRACE_PREFIX = "AGENT_TRACE "


def discover_sources(input_root: Path, output_root: Path) -> list[dict]:
    sources = []
    for path in sorted(input_root.rglob("*")):
        if not path.is_file():
            continue
        if ".log" not in [suffix.lower() for suffix in path.suffixes]:
            continue
        if "-label.log" in path.name.lower():
            continue
        relative = path.relative_to(input_root)
        output_dir = output_root / relative.with_suffix("")
        result_files = sorted(
            [
                item.name
                for item in output_dir.glob("*.csv")
                if item.name not in {"preprocessed.csv", "group.csv"} and item.stem.isdigit()
            ],
            key=_csv_sort_key,
        )
        sources.append(
            {
                "source": relative.as_posix(),
                "size_bytes": path.stat().st_size,
                "output_available": output_dir.exists(),
                "has_preprocessed": (output_dir / "preprocessed.csv").is_file(),
                "has_group": (output_dir / "group.csv").is_file(),
                "has_group_tree": (output_dir / "group_tree.json").is_file(),
                "result_files": result_files,
            }
        )
    return sources


def discover_source_folders(
    input_root: Path,
    output_root: Path,
    schemas_root: Path,
    limit: int = 80,
) -> dict:
    input_root = Path(input_root).resolve()
    output_root = Path(output_root).resolve()
    schemas_root = Path(schemas_root).resolve()
    sources = discover_sources(input_root, output_root)
    sources_by_folder: dict[str, list[dict]] = {}
    for source in sources:
        folder = Path(str(source.get("source") or "")).parent.as_posix()
        if folder == ".":
            folder = ""
        sources_by_folder.setdefault(folder, []).append(source)

    folders = []
    for path in sorted(item for item in input_root.rglob("*") if item.is_dir()):
        relative = path.relative_to(input_root).as_posix()
        direct_sources = sources_by_folder.get(relative, [])
        descendant_prefix = f"{relative}/"
        descendant_sources = [
            source
            for source in sources
            if str(source.get("source") or "").startswith(descendant_prefix)
            and Path(str(source.get("source") or "")).parent.as_posix() != relative
        ]
        schema_type = _schema_family_for_text(relative)
        poi_path = _schema_path_for_family(schema_type, "poi", schemas_root)
        relation_path = _schema_path_for_family(schema_type, "relation", schemas_root)
        folders.append(
            {
                "folder": relative,
                "label": path.name,
                "parent": "" if path.parent == input_root else path.parent.relative_to(input_root).as_posix(),
                "direct_log_count": len(direct_sources),
                "log_count": len(direct_sources) + len(descendant_sources),
                "ready_count": sum(
                    1
                    for source in [*direct_sources, *descendant_sources]
                    if source.get("output_available")
                ),
                "schema_type": schema_type or "",
                "poi_schema_path": str(poi_path) if poi_path else "",
                "relation_schema_path": str(relation_path) if relation_path else "",
                "poi_schema": read_poi_preview(poi_path, limit)
                if poi_path
                else {"available": False, "columns": [], "rows": [], "truncated": False},
            }
        )
    return {"available": True, "folders": folders}


def match_sources(input_root: Path, output_root: Path, project: str) -> list[dict]:
    sources = discover_sources(input_root, output_root)
    selectors = [item.strip().replace("\\", "/") for item in project.split(",") if item.strip()]
    if not selectors or selectors == ["all"]:
        return sources

    matched = []
    seen = set()
    for item in sources:
        source = item["source"]
        source_path = Path(source)
        source_stem = str(source_path.with_suffix("")).replace("\\", "/")
        parts = {part.lower() for part in source_path.parts}
        for selector in selectors:
            selector_lower = selector.lower()
            if (
                selector_lower == source.lower()
                or selector_lower == source_stem.lower()
                or selector_lower == source_path.name.lower()
                or selector_lower == source_path.stem.lower()
                or selector_lower in source.lower()
                or selector_lower in parts
            ):
                if source not in seen:
                    matched.append(item)
                    seen.add(source)
                break
    return matched


def read_raw_preview(path: Path, limit: int) -> tuple[list[dict], bool]:
    rows = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as file:
        for index, line in enumerate(file, start=1):
            if index > limit:
                return rows, True
            rows.append({"Line": index, "Content": line.rstrip("\r\n")})
    return rows, False


def read_csv_preview(path: Path, limit: int) -> dict:
    if not path.is_file():
        return {"available": False, "columns": [], "rows": [], "truncated": False}
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        rows = []
        truncated = False
        for index, row in enumerate(reader, start=1):
            if index > limit:
                truncated = True
                break
            rows.append(row)
    return {
        "available": True,
        "columns": reader.fieldnames or [],
        "rows": rows,
        "truncated": truncated,
    }


def read_firewall_poi_result_preview(output_root: Path, output_dir: Path, limit: int) -> dict:
    poi_result = read_csv_preview(output_dir / "customer_event_params.csv", limit)
    if not poi_result.get("available"):
        return poi_result
    customer_events = read_customer_event_preview(output_root, output_dir, limit)
    return merge_customer_events_into_poi_preview(poi_result, customer_events)


def merge_customer_events_into_poi_preview(poi_result: dict, customer_events: dict) -> dict:
    if not customer_events.get("available"):
        return poi_result

    event_rows = [
        row
        for row in customer_events.get("rows", [])
        if isinstance(row, dict)
    ]
    if not event_rows:
        return poi_result

    events_by_key: dict[tuple[str, ...], list[int]] = {}
    for event_index, event_row in enumerate(event_rows):
        for key in _customer_event_match_keys(event_row):
            events_by_key.setdefault(key, []).append(event_index)

    rows = []
    used_event_indexes: set[int] = set()
    for index, raw_row in enumerate(poi_result.get("rows", [])):
        row = dict(raw_row)
        event_index = None
        for key in _poi_result_match_keys(row):
            queue = events_by_key.get(key) or []
            while queue and queue[0] in used_event_indexes:
                queue.pop(0)
            if queue:
                event_index = queue.pop(0)
                break
        if event_index is None and index < len(event_rows) and index not in used_event_indexes:
            event_index = index
        if event_index is not None:
            used_event_indexes.add(event_index)
            _merge_customer_event_into_poi_row(row, event_rows[event_index])
        rows.append(row)

    return {
        **poi_result,
        "rows": rows,
    }


def _merge_customer_event_into_poi_row(row: dict, event_row: dict) -> None:
    alarm_type = str(event_row.get("alarm_type") or "").strip()
    if alarm_type in {"1", "2", "3"}:
        _fill_display_value(row, "event_type", "admin_session")
        _fill_display_value(row, "event_action", "login")
    elif alarm_type == "4":
        _fill_display_value(row, "event_type", "policy_rule")
        _fill_display_value(row, "event_action", _canonical_action(event_row.get("action")))

    for poi_field, event_fields in CUSTOMER_EVENT_POI_ALIASES.items():
        value = _first_display_value(event_row, event_fields)
        if poi_field == "policy_type":
            value = _canonical_policy(value)
        _fill_display_value(row, poi_field, value)


def _first_display_value(row: dict, fields: tuple[str, ...]) -> str:
    for field in fields:
        value = str(row.get(field) or "").strip()
        if value:
            return value
    return ""


def _fill_display_value(row: dict, field: str, value) -> None:
    if str(row.get(field) or "").strip():
        return
    text = str(value or "").strip()
    if text:
        row[field] = text


def _canonical_action(value) -> str:
    text = str(value or "").strip()
    return CUSTOMER_ACTION_TO_POI.get(text, text)


def _canonical_policy(value) -> str:
    text = str(value or "").strip()
    return CUSTOMER_POLICY_TO_POI.get(text, text)


def _customer_event_match_keys(row: dict) -> tuple[tuple[str, ...], ...]:
    return _unique_match_keys(
        _compact_match_key(row.get("login_time"), row.get("control_name"), row.get("login_account")),
        _compact_match_key(row.get("login_time"), row.get("login_account")),
        _compact_match_key(row.get("login_time"), row.get("src_ip") or row.get("control_ip")),
        _compact_match_key(row.get("login_time"), row.get("dst_ip") or row.get("control_ip")),
        _compact_match_key(row.get("login_time")),
    )


def _poi_result_match_keys(row: dict) -> tuple[tuple[str, ...], ...]:
    time_value = row.get("login_time") or row.get("time")
    return _unique_match_keys(
        _compact_match_key(time_value, row.get("control_name") or row.get("device_name"), row.get("login_account") or row.get("user")),
        _compact_match_key(time_value, row.get("login_account") or row.get("user")),
        _compact_match_key(time_value, row.get("src_ip") or row.get("management_ip") or row.get("src_addr")),
        _compact_match_key(time_value, row.get("dst_ip") or row.get("dst_addr")),
        _compact_match_key(time_value),
    )


def _compact_match_key(*values) -> tuple[str, ...]:
    key = tuple(str(value or "").strip().casefold() for value in values)
    return key if any(key) else ()


def _unique_match_keys(*keys: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return tuple(dict.fromkeys(key for key in keys if key))


def read_poi_preview(path: Path, limit: int) -> dict:
    if not path.is_file():
        return {"available": False, "columns": [], "rows": [], "truncated": False}
    rows = []
    truncated = False
    for index, row in enumerate(read_poi_rows(path), start=1):
        if index > limit:
            truncated = True
            break
        rows.append(row)
    return {
        "available": True,
        "columns": ["field", "description"],
        "rows": rows,
        "truncated": truncated,
    }


def read_summary(output_root: Path) -> dict:
    summaries = sorted(output_root.glob("summary_raw_[sample_size=*].csv"))
    if not summaries:
        return {"available": False, "files": []}
    files = [{"file": path.name, **read_csv_preview(path, 200)} for path in summaries]
    return {"available": True, "files": files}


def load_source_payload(input_root: Path, output_root: Path, source: str, sample: str, limit: int) -> dict:
    input_root = Path(input_root).resolve()
    output_root = Path(output_root).resolve()
    raw_path = _safe_join(input_root, source)
    if not raw_path.is_file():
        raise FileNotFoundError(source)

    relative = raw_path.relative_to(input_root)
    output_dir = output_root / relative.with_suffix("")
    result_name = f"{sample}.csv" if sample else _latest_result_file(output_dir)
    if result_name and not (output_dir / result_name).is_file():
        result_name = _latest_result_file(output_dir)
    raw_rows, raw_truncated = read_raw_preview(raw_path, limit)

    return {
        "source": relative.as_posix(),
        "input": {
            "path": str(raw_path),
            "rows": raw_rows,
            "truncated": raw_truncated,
        },
        "output_dir": str(output_dir),
        "preprocessed": read_csv_preview(output_dir / "preprocessed.csv", limit),
        "group": read_csv_preview(output_dir / "group.csv", limit),
        "result": read_csv_preview(output_dir / result_name, limit)
        if result_name
        else {"available": False, "columns": [], "rows": [], "truncated": False},
        "result_file": result_name,
        "group_tree": read_group_tree_summary(output_dir / "group_tree.json"),
        "schema_meta": read_json_file(output_dir / "schema_meta.json"),
        "poi_schema": _read_schema_preview(output_dir, "poi_schema.csv", source, "poi", limit),
        "relation_schema": _read_schema_preview(output_dir, "relation_schema.csv", source, "relation", limit),
        "poi_result": read_firewall_poi_result_preview(output_root, output_dir, limit),
        "customer_events": read_customer_event_preview(output_root, output_dir, limit),
    }


def _read_schema_preview(output_dir: Path, filename: str, source: str, kind: str, limit: int) -> dict:
    local_path = output_dir / filename
    if local_path.is_file():
        if kind == "poi":
            return read_poi_preview(local_path, limit)
        return read_csv_preview(local_path, limit)
    schema_path = _canonical_schema_path(source, kind)
    if schema_path and kind == "poi":
        return read_poi_preview(schema_path, limit)
    return read_csv_preview(schema_path, limit) if schema_path else read_csv_preview(local_path, limit)


def _canonical_schema_path(source: str, kind: str) -> Path | None:
    family = _schema_family_for_text(source)
    return _schema_path_for_family(family, kind, FrontendHandler.schemas_root)


def _schema_family_for_text(text: str) -> str | None:
    source_lower = str(text or "").replace("\\", "/").lower()
    for family, markers in SCHEMA_FAMILY_MARKERS:
        if any(marker.lower() in source_lower for marker in markers):
            return family
    return None


def _schema_path_for_family(family: str | None, kind: str, schemas_root: Path) -> Path | None:
    if not family:
        return None
    suffix = "POI.csv" if kind == "poi" else "relation.csv"
    path = Path(schemas_root) / f"{family}_{suffix}"
    if path.is_file():
        return path
    if family == "openvpn":
        fallback = Path(schemas_root) / f"vpn_{suffix}"
        if fallback.is_file():
            return fallback
    return None


def poi_schema_payload(input_root: Path, output_root: Path, source: str) -> dict:
    paths = _poi_schema_paths(input_root, output_root, source)
    active_path = paths["local_path"] if paths["local_path"].is_file() else paths["canonical_path"]
    rows = read_poi_rows(active_path) if active_path and active_path.is_file() else []
    validation = validate_poi_rows(rows, paths["relation_path"])
    return {
        "source": paths["source"],
        "available": bool(active_path and active_path.is_file()),
        "active_path": str(active_path) if active_path else "",
        "canonical_path": str(paths["canonical_path"]) if paths["canonical_path"] else "",
        "local_path": str(paths["local_path"]),
        "relation_path": str(paths["relation_path"]) if paths["relation_path"] else "",
        "rows": rows,
        "validation": validation,
    }


def _poi_schema_paths(input_root: Path, output_root: Path, source: str) -> dict:
    input_root = Path(input_root).resolve()
    output_root = Path(output_root).resolve()
    raw_path = _safe_join(input_root, source)
    if not raw_path.is_file():
        raise FileNotFoundError(source)
    relative = raw_path.relative_to(input_root)
    output_dir = output_root / relative.with_suffix("")
    local_path = output_dir / "poi_schema.csv"
    canonical_path = _canonical_schema_path(source, "poi")
    relation_path = output_dir / "relation_schema.csv"
    if not relation_path.is_file():
        relation_path = _canonical_schema_path(source, "relation")
    return {
        "source": relative.as_posix(),
        "output_dir": output_dir,
        "local_path": local_path,
        "canonical_path": canonical_path,
        "relation_path": relation_path,
    }


def read_poi_rows(path: Path) -> list[dict]:
    rows = []
    if not path or not Path(path).is_file():
        return rows
    with Path(path).open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)
        for index, row in enumerate(reader, start=1):
            if not row or not any(cell.strip() for cell in row):
                continue
            if index == 1 and len(row) >= 2 and row[0].strip().lower() == "field":
                continue
            rows.append(
                {
                    "field": row[0].strip() if row else "",
                    "description": row[1].strip() if len(row) > 1 else "",
                }
            )
    return rows


def write_poi_rows(path: Path, rows: list[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        for row in rows:
            writer.writerow([str(row.get("field", "")).strip(), str(row.get("description", "")).strip()])


def validate_poi_rows(rows: list[dict], relation_path: Path | None = None) -> dict:
    errors = []
    warnings = []
    normalized_rows = []
    seen = {}
    suspicious_names = {
        "a",
        "aa",
        "aaa",
        "asdf",
        "bar",
        "field",
        "foo",
        "null",
        "none",
        "test",
        "tmp",
        "todo",
        "unknown",
        "xxx",
    }

    if not isinstance(rows, list):
        return {
            "ok": False,
            "errors": ["POI rows must be an array."],
            "warnings": [],
            "normalized_rows": [],
        }

    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            errors.append(f"Row {index}: item must be an object.")
            continue
        field = str(row.get("field") or "").strip()
        description = str(row.get("description") or "").strip()
        normalized = _normalize_poi_field(field)
        normalized_rows.append({"field": field, "description": description})

        if not field:
            errors.append(f"Row {index}: field is required.")
            continue
        if field != normalized:
            errors.append(
                f"Row {index}: field '{field}' must be lower_snake_case; suggested '{normalized}'."
            )
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", field):
            errors.append(
                f"Row {index}: field '{field}' must start with a letter and contain 2-64 lowercase letters, numbers, or underscores."
            )
        if field in seen:
            errors.append(f"Row {index}: duplicate field '{field}' also appears on row {seen[field]}.")
        seen[field] = index

        if not description:
            warnings.append(f"Row {index}: '{field}' has no description.")
        elif len(description) < 12:
            warnings.append(f"Row {index}: '{field}' description is very short.")
        elif len(description) > 500:
            errors.append(f"Row {index}: '{field}' description is longer than 500 characters.")

        if field in suspicious_names or re.fullmatch(r"(.)\1{2,}", field):
            warnings.append(f"Row {index}: '{field}' looks like a placeholder name.")

    field_names = {row["field"] for row in normalized_rows if row.get("field")}
    if not field_names:
        errors.append("At least one POI field is required.")
    elif not (field_names & {"host", "program", "event_type", "event_action", "user", "src_ip", "dst_ip", "outcome", "object", "target"}):
        warnings.append(
            "No common graph anchor field was found. Consider including fields such as host, program, event_type, user, src_ip, dst_ip, or outcome when present."
        )
    if len(field_names) > 80:
        warnings.append("POI has more than 80 fields; POI should stay focused on KG-relevant fields.")

    relation_refs = _relation_poi_refs(relation_path)
    missing_refs = sorted(ref for ref in relation_refs if ref and ref not in field_names)
    if missing_refs:
        errors.append(
            "Relation schema references missing POI fields: " + ", ".join(missing_refs)
        )

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "normalized_rows": normalized_rows,
        "field_count": len(field_names),
        "relation_ref_count": len(relation_refs),
    }


def save_poi_schema(input_root: Path, output_root: Path, source: str, rows: list[dict]) -> dict:
    paths = _poi_schema_paths(input_root, output_root, source)
    validation = validate_poi_rows(rows, paths["relation_path"])
    if not validation["ok"]:
        return {
            "ok": False,
            "validation": validation,
            "saved_paths": [],
        }

    rows_to_write = validation["normalized_rows"]
    saved_paths = []
    if paths["canonical_path"]:
        write_poi_rows(paths["canonical_path"], rows_to_write)
        saved_paths.append(str(paths["canonical_path"]))
    if paths["local_path"].parent.is_dir():
        write_poi_rows(paths["local_path"], rows_to_write)
        saved_paths.append(str(paths["local_path"]))
    if not saved_paths:
        write_poi_rows(paths["local_path"], rows_to_write)
        saved_paths.append(str(paths["local_path"]))

    return {
        "ok": True,
        "source": paths["source"],
        "saved_paths": saved_paths,
        "validation": validation,
    }


def _normalize_poi_field(field: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", field.strip()).strip("_").lower()


def _relation_poi_refs(path: Path | None) -> set[str]:
    refs = set()
    if not path or not Path(path).is_file():
        return refs
    with Path(path).open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            for column in ("subject_id_source", "object_id_source"):
                refs.add(_normalize_poi_field(row.get(column) or ""))
            for raw_field in str(row.get("edge_properties") or "").split(","):
                refs.add(_normalize_poi_field(raw_field))
    refs.discard("")
    return refs


def read_group_tree_summary(path: Path) -> dict:
    if not path.is_file():
        return {"available": False}
    with path.open("r", encoding="utf-8") as file:
        tree = json.load(file)
    clusters = tree.get("clusters", [])
    return {
        "available": True,
        "line_count": tree.get("line_count", 0),
        "group_count": tree.get("group_count", 0),
        "clusters": clusters[:50],
        "truncated": len(clusters) > 50,
    }


def read_json_file(path: Path) -> dict:
    if not path.is_file():
        return {"available": False}
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    payload["available"] = True
    return payload


def read_customer_event_preview(output_root: Path, output_dir: Path, limit: int) -> dict:
    events_path = _customer_event_artifact_path(
        output_root,
        output_dir,
        "customer_events.json",
    )
    validation_path = _customer_event_artifact_path(
        output_root,
        output_dir,
        "customer_event_validation.json",
    )
    if not events_path.is_file():
        return {
            "available": False,
            "columns": [],
            "rows": [],
            "truncated": False,
            "validation": {"available": False},
            "path": "",
        }

    with events_path.open("r", encoding="utf-8") as file:
        events = json.load(file)
    if not isinstance(events, list):
        raise ValueError(f"客户事件文件必须是 JSON 数组: {events_path}")

    columns = ["alarm_type"]
    flattened = []
    for event in events[:limit]:
        data = event.get("data") if isinstance(event, dict) else {}
        data = data if isinstance(data, dict) else {}
        row = {"alarm_type": event.get("alarm_type", "") if isinstance(event, dict) else ""}
        row.update(data)
        flattened.append(row)
        for field in data:
            if field not in columns:
                columns.append(field)

    validation = read_json_file(validation_path)
    return {
        "available": True,
        "columns": columns,
        "rows": flattened,
        "truncated": len(events) > limit,
        "validation": validation,
        "path": str(events_path),
        "event_count": len(events),
    }


def _customer_event_artifact_path(output_root: Path, output_dir: Path, filename: str) -> Path:
    local_path = output_dir / filename
    if local_path.is_file():
        return local_path
    try:
        relative = output_dir.resolve().relative_to(Path(output_root).resolve())
    except ValueError:
        return local_path
    edc_path = EDC_AIT_ROOT / relative / filename
    return edc_path if edc_path.is_file() else local_path


def export_customer_events_for_parsed_outputs(
    input_root: Path,
    output_root: Path,
    schemas_root: Path,
    project: str,
) -> dict:
    input_root = Path(input_root).resolve()
    output_root = Path(output_root).resolve()
    schemas_root = Path(schemas_root).resolve()
    report = {
        "checked": 0,
        "generated": 0,
        "skipped": 0,
        "failed": 0,
        "items": [],
    }
    for source in match_sources(input_root, output_root, project):
        source_name = str(source.get("source") or "").replace("\\", "/")
        if not source_name:
            continue
        output_dir = output_root / Path(source_name).with_suffix("")
        report["checked"] += 1
        if not output_dir.is_dir():
            _customer_event_report_item(report, source_name, "skipped", "解析输出目录不存在")
            continue
        if not _is_firewall_parser_output(output_dir, source_name):
            _customer_event_report_item(report, source_name, "skipped", "不是 firewall schema")
            continue
        result_csv = _latest_result_csv_path(output_dir)
        if result_csv is None:
            _customer_event_report_item(report, source_name, "skipped", "没有数字结果 CSV")
            continue
        try:
            params_csv = _extract_firewall_params_for_customer_events(
                result_csv=result_csv,
                output_dir=output_dir,
            )
            written = _export_customer_events_from_params(
                params_csv=params_csv,
                output_dir=output_dir,
                schemas_root=schemas_root,
                source_name=source_name,
            )
        except Exception as exc:
            _customer_event_report_item(report, source_name, "failed", str(exc))
            continue
        _customer_event_report_item(
            report,
            source_name,
            "generated",
            f"生成 {Path(written['events']).name}",
            path=written["events"],
        )
    return report


def _customer_event_report_item(
    report: dict,
    source: str,
    status: str,
    message: str,
    *,
    path: str = "",
) -> None:
    if status in {"generated", "skipped", "failed"}:
        report[status] += 1
    report["items"].append(
        {
            "source": source,
            "status": status,
            "message": message,
            "path": path,
        }
    )


def _is_firewall_parser_output(output_dir: Path, source_name: str) -> bool:
    text = f"{source_name} {output_dir.as_posix()}".casefold()
    path_is_firewall = "firewall" in text or "防火墙" in text
    meta_path = output_dir / "schema_meta.json"
    if meta_path.is_file():
        try:
            with meta_path.open("r", encoding="utf-8") as file:
                meta = json.load(file)
            schema_type = str(meta.get("schema_type") or "").strip().casefold()
            if schema_type:
                return schema_type == "firewall" or path_is_firewall
        except Exception:
            pass
    return path_is_firewall


def _latest_result_csv_path(output_dir: Path) -> Path | None:
    name = _latest_result_file(output_dir)
    return output_dir / name if name else None


def _extract_firewall_params_for_customer_events(*, result_csv: Path, output_dir: Path) -> Path:
    extractor = EDC_ROOT / "extract_firewall_example_params.py"
    if not extractor.is_file():
        raise FileNotFoundError(extractor)
    params_csv = output_dir / "customer_event_params.csv"
    command = [
        sys.executable,
        str(extractor),
        "--input-csv",
        str(result_csv),
        "--pairs-json",
        str(output_dir / "customer_event_pairs.json"),
        "--output-csv",
        str(params_csv),
        "--log-source",
        "firewall",
    ]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        command,
        cwd=EDC_ROOT,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env=env,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "防火墙客户事件参数抽取失败"
            f"\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return params_csv


def _export_customer_events_from_params(
    *,
    params_csv: Path,
    output_dir: Path,
    schemas_root: Path,
    source_name: str,
) -> dict[str, str]:
    if EDC_ROOT.is_dir() and str(EDC_ROOT) not in sys.path:
        sys.path.insert(0, str(EDC_ROOT))
    from log_pipeline_agent.firewall_events import (
        enrich_params_csv_with_customer_defaults,
        export_customer_events,
    )

    enrich_params_csv_with_customer_defaults(
        params_csv=params_csv,
        asset_path=schemas_root / "firewall_assets.csv",
        device_path=schemas_root / "firewall_devices.csv",
        source_name=source_name,
    )
    payload = export_customer_events(
        params_csv=params_csv,
        output_dirs=(output_dir,),
        schema_path=schemas_root / "firewall_customer_event_schema.json",
        asset_path=schemas_root / "firewall_assets.csv",
        device_path=schemas_root / "firewall_devices.csv",
        source_name=source_name,
    )
    return payload["written"][-1]


def _latest_result_file(output_dir: Path) -> str | None:
    if not output_dir.is_dir():
        return None
    candidates = [
        path.name
        for path in output_dir.glob("*.csv")
        if path.name not in {"preprocessed.csv", "group.csv"} and path.stem.isdigit()
    ]
    if not candidates:
        return None
    return sorted(candidates, key=_csv_sort_key)[-1]


def _csv_sort_key(name: str) -> tuple[int, int | str]:
    stem = Path(name).stem
    return (0, int(stem)) if stem.isdigit() else (1, name)


def _safe_join(root: Path, relative: str) -> Path:
    target = (root / relative).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError("Path is outside of the configured root.")
    return target


class RunManager:
    def __init__(self, input_root: Path, output_root: Path, schemas_root: Path):
        self.input_root = Path(input_root).resolve()
        self.output_root = Path(output_root).resolve()
        self.schemas_root = Path(schemas_root).resolve()
        self.lock = threading.Lock()
        self.process = None
        self.reader_thread = None
        self.run_id = 0
        self.state = self._empty_state()

    def configure(self, input_root: Path, output_root: Path, schemas_root: Path) -> None:
        with self.lock:
            self.input_root = Path(input_root).resolve()
            self.output_root = Path(output_root).resolve()
            self.schemas_root = Path(schemas_root).resolve()

    def start(self, payload: dict) -> tuple[bool, str]:
        with self.lock:
            if self.process and self.process.poll() is None:
                return False, "已有解析任务正在运行。"

            self.run_id += 1
            run_id = self.run_id
            project = str(payload.get("project") or "all").strip() or "all"
            sample = int(payload.get("sample") or 3)
            model = str(payload.get("model") or DEFAULT_LLM_MODEL_ID).strip()
            similarity = str(payload.get("similarity") or "jaccard").strip()
            do_self_reflection = "True" if payload.get("doSelfReflection", True) else "False"
            write_group_tree = bool(payload.get("writeGroupTree", True))
            preserve_existing = bool(payload.get("preserveExisting", False))
            planner_enabled = bool(payload.get("plannerEnabled", True))
            api_key = str(payload.get("api_key") or "").strip()
            if not api_key:
                return False, "GLM API Key 必须从前端输入，后端不再读取 .env。"
            matched_sources = match_sources(self.input_root, self.output_root, project)

            command = [
                sys.executable,
                "-u",
                "evaluation.py",
                "--project",
                project,
                "--model",
                model,
                "--sample",
                str(sample),
                "--similarity",
                similarity,
                "--do_self_reflection",
                do_self_reflection,
                "--input_dir",
                str(self.input_root),
                "--output_dir",
                str(self.output_root),
                "--schemas_dir",
                str(self.schemas_root),
                "--api_key",
                api_key,
                "--api_key_env",
                "",
                "--api_base",
                DEFAULT_GLM_BASE_URL,
                "--temperature",
                "0.1",
            ]
            if write_group_tree:
                command.append("--write_group_tree")
            if preserve_existing:
                command.append("--preserve_existing")
            if not planner_enabled:
                command.append("--disable_planner")

            env = os.environ.copy()
            for secret_key in LLM_SECRET_ENV_KEYS:
                env.pop(secret_key, None)
            env["PYTHONUNBUFFERED"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"
            self.state = {
                "id": run_id,
                "status": "running",
                "running": True,
                "started_at": _now_text(),
                "ended_at": "",
                "returncode": None,
                "command": _display_command(command),
                "project": project,
                "sample": sample,
                "model": model,
                "similarity": similarity,
                "total_sources": len(matched_sources),
                "completed_sources": 0,
                "current_source": "",
                "message": "解析任务已启动。",
                "logs": [],
                "traces": [],
            }

            self.process = subprocess.Popen(
                command,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
            )
            self.reader_thread = threading.Thread(
                target=self._read_output, args=(run_id,), daemon=True
            )
            self.reader_thread.start()
            return True, "解析任务已启动。"

    def stop(self) -> tuple[bool, str]:
        with self.lock:
            if not self.process or self.process.poll() is not None:
                return False, "当前没有正在运行的解析任务。"
            self.state["status"] = "stopping"
            self.state["message"] = "正在停止解析任务。"
            self.process.terminate()
            return True, "已发送停止信号。"

    def status(self, tail: int = 300) -> dict:
        with self.lock:
            state = dict(self.state)
            state["logs"] = self.state["logs"][-tail:]
            state["traces"] = self.state.get("traces", [])[-tail:]
            total = state.get("total_sources") or 0
            completed = state.get("completed_sources") or 0
            state["progress"] = completed / total if total else 0
            return state

    def _read_output(self, run_id: int) -> None:
        process = self.process
        if process.stdout:
            for line in process.stdout:
                self._append_log(run_id, line.rstrip("\r\n"))
        returncode = process.wait()
        with self.lock:
            if self.state.get("id") != run_id:
                return
            self.state["running"] = False
            self.state["returncode"] = returncode
            self.state["ended_at"] = _now_text()
            if self.state["status"] == "stopping":
                self.state["status"] = "stopped"
                self.state["message"] = "解析任务已停止。"
            elif returncode == 0:
                self.state["status"] = "succeeded"
                customer_event_report = export_customer_events_for_parsed_outputs(
                    self.input_root,
                    self.output_root,
                    self.schemas_root,
                    str(self.state.get("project") or "all"),
                )
                self.state["logs"].append(
                    "Customer event export: "
                    f"generated={customer_event_report['generated']}, "
                    f"skipped={customer_event_report['skipped']}, "
                    f"failed={customer_event_report['failed']}"
                )
                if customer_event_report["failed"]:
                    failed_sources = [
                        item["source"]
                        for item in customer_event_report["items"]
                        if item["status"] == "failed"
                    ]
                    self.state["message"] = (
                        "解析任务已完成，但客户事件 JSON 生成失败: "
                        + ", ".join(failed_sources[:3])
                    )
                elif customer_event_report["generated"]:
                    self.state["message"] = (
                        "解析任务已完成，已生成 "
                        f"{customer_event_report['generated']} 个客户事件 JSON。"
                    )
                else:
                    self.state["message"] = "解析任务已完成。"
            else:
                self.state["status"] = "failed"
                self.state["message"] = f"解析任务失败，退出码 {returncode}。"

    def _append_log(self, run_id: int, line: str) -> None:
        clean_line = line.replace("\r", "").strip()
        if not clean_line:
            return
        completed_source = ""
        with self.lock:
            if self.state.get("id") != run_id:
                return
            self.state["logs"].append(clean_line)
            if len(self.state["logs"]) > MAX_RUN_LOG_LINES:
                self.state["logs"] = self.state["logs"][-MAX_RUN_LOG_LINES:]
            if clean_line.startswith("Start Agent Parsing "):
                self.state["current_source"] = clean_line.replace("Start Agent Parsing ", "", 1)
                self.state["message"] = f"正在解析 {self.state['current_source']}"
            elif "Timestamp preprocessing finished" in clean_line:
                self.state["message"] = "时间戳预处理完成，正在分组。"
            elif "deep grouping tree finished" in clean_line:
                self.state["message"] = "深度分组树完成，正在解析模板。"
            elif " Agent parsing done." in clean_line:
                self.state["completed_sources"] += 1
                self.state["message"] = "一个日志源解析完成。"
                completed_source = clean_line.split(" Agent parsing done.", 1)[0].strip()
                if not completed_source:
                    completed_source = str(self.state.get("current_source") or "").strip()
            if clean_line.startswith(TRACE_PREFIX):
                try:
                    event = json.loads(clean_line[len(TRACE_PREFIX) :])
                    self.state.setdefault("traces", []).append(event)
                    if len(self.state["traces"]) > MAX_RUN_LOG_LINES:
                        self.state["traces"] = self.state["traces"][-MAX_RUN_LOG_LINES:]
                except json.JSONDecodeError:
                    pass
        if completed_source:
            self._export_customer_events_for_source(run_id, completed_source)

    def _export_customer_events_for_source(self, run_id: int, source_name: str) -> None:
        source_name = source_name.strip().replace("\\", "/")
        if not source_name:
            return
        try:
            report = export_customer_events_for_parsed_outputs(
                self.input_root,
                self.output_root,
                self.schemas_root,
                source_name,
            )
        except Exception as exc:
            report = {
                "checked": 1,
                "generated": 0,
                "skipped": 0,
                "failed": 1,
                "items": [
                    {
                        "source": source_name,
                        "status": "failed",
                        "message": str(exc),
                        "path": "",
                    }
                ],
            }
        with self.lock:
            if self.state.get("id") != run_id:
                return
            self.state["logs"].append(
                "Customer event export for "
                f"{source_name}: generated={report['generated']}, "
                f"skipped={report['skipped']}, failed={report['failed']}"
            )
            if len(self.state["logs"]) > MAX_RUN_LOG_LINES:
                self.state["logs"] = self.state["logs"][-MAX_RUN_LOG_LINES:]
            if report["failed"]:
                self.state["message"] = "一个日志源解析完成，但客户事件 JSON 生成失败。"
            elif report["generated"]:
                self.state["message"] = "一个日志源解析完成，客户事件 JSON 已生成。"

    def _empty_state(self) -> dict:
        return {
            "id": 0,
            "status": "idle",
            "running": False,
            "started_at": "",
            "ended_at": "",
            "returncode": None,
            "command": "",
            "project": "",
            "sample": 3,
            "model": DEFAULT_LLM_MODEL_ID,
            "similarity": "jaccard",
            "total_sources": 0,
            "completed_sources": 0,
            "current_source": "",
            "message": "空闲。",
            "logs": [],
            "traces": [],
        }


def _now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _display_command(command: list[str]) -> str:
    redacted: list[str] = []
    hide_next = False
    for part in command:
        text = str(part)
        if hide_next:
            redacted.append("***" if text else "")
            hide_next = False
            continue
        redacted.append(text)
        if text in {"--api_key", "--api-key"}:
            hide_next = True
    return " ".join(redacted)


def _alarm_list_payload(query: dict) -> dict:
    try:
        page = max(1, int(query.get("page", ["1"])[0]))
        page_size = max(1, int(query.get("page_size", ["10"])[0]))
    except (TypeError, ValueError):
        page = 1
        page_size = 10

    event_list = extra_api.get_alarm_list()
    total = len(event_list)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": event_list[start_idx:end_idx],
    }


class FrontendHandler(SimpleHTTPRequestHandler):
    input_root = REPO_ROOT / "full_dataset"
    output_root = REPO_ROOT / "result_deepseek"
    schemas_root = REPO_ROOT / "schemas"
    run_manager = RunManager(input_root, output_root, schemas_root)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/sources":
                self._send_json(discover_sources(self.input_root, self.output_root))
                return
            if parsed.path == "/api/source-folders":
                query = parse_qs(parsed.query)
                self._send_json(
                    discover_source_folders(
                        self.input_root,
                        self.output_root,
                        self.schemas_root,
                        int(query.get("limit", ["80"])[0]),
                    )
                )
                return
            if parsed.path == "/api/source":
                query = parse_qs(parsed.query)
                payload = load_source_payload(
                    self.input_root,
                    self.output_root,
                    query.get("source", [""])[0],
                    query.get("sample", ["3"])[0],
                    int(query.get("limit", ["80"])[0]),
                )
                self._send_json(payload)
                return
            if parsed.path == "/api/summary":
                self._send_json(read_summary(self.output_root))
                return
            if parsed.path == "/api/poi/schema":
                query = parse_qs(parsed.query)
                self._send_json(
                    poi_schema_payload(
                        self.input_root,
                        self.output_root,
                        query.get("source", [""])[0],
                    )
                )
                return
            if parsed.path == "/api/run/status":
                query = parse_qs(parsed.query)
                self._send_json(self.run_manager.status(tail=int(query.get("tail", ["300"])[0])))
                return
            if parsed.path == "/api/alarm/list":
                query = parse_qs(parsed.query)
                self._send_json(_alarm_list_payload(query))
                return
            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/run/start":
                payload = self._read_json_body()
                ok, message = self.run_manager.start(payload)
                self._send_json(
                    {"ok": ok, "message": message, "status": self.run_manager.status()},
                    status=HTTPStatus.OK if ok else HTTPStatus.CONFLICT,
                )
                return
            if parsed.path == "/api/run/stop":
                ok, message = self.run_manager.stop()
                self._send_json(
                    {"ok": ok, "message": message, "status": self.run_manager.status()},
                    status=HTTPStatus.OK if ok else HTTPStatus.CONFLICT,
                )
                return
            if parsed.path == "/api/poi/validate":
                payload = self._read_json_body()
                source = str(payload.get("source") or "").strip()
                relation_path = None
                if source:
                    relation_path = _poi_schema_paths(
                        self.input_root, self.output_root, source
                    )["relation_path"]
                self._send_json(validate_poi_rows(payload.get("rows") or [], relation_path))
                return
            if parsed.path == "/api/poi/save":
                payload = self._read_json_body()
                result = save_poi_schema(
                    self.input_root,
                    self.output_root,
                    str(payload.get("source") or "").strip(),
                    payload.get("rows") or [],
                )
                self._send_json(
                    result,
                    status=HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST,
                )
                return
            
            if parsed.path == "/api/alarm/list":
                self._send_json(_alarm_list_payload(parse_qs(parsed.query)))
                return
            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def _send_json(self, payload, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        body = self.rfile.read(length).decode("utf-8")
        return json.loads(body) if body.strip() else {}

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--input_dir", default=str(REPO_ROOT / "full_dataset"))
    parser.add_argument("--output_dir", default=str(REPO_ROOT / "result_deepseek"))
    parser.add_argument("--schemas_dir", default=str(REPO_ROOT / "schemas"))
    args = parser.parse_args(argv)

    FrontendHandler.input_root = Path(args.input_dir).resolve()
    FrontendHandler.output_root = Path(args.output_dir).resolve()
    FrontendHandler.schemas_root = Path(args.schemas_dir).resolve()
    FrontendHandler.run_manager.configure(
        FrontendHandler.input_root,
        FrontendHandler.output_root,
        FrontendHandler.schemas_root,
    )
    server = ThreadingHTTPServer((args.host, args.port), FrontendHandler)
    print(f"Backend API server: http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
