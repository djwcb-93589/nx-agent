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
import shutil
import subprocess
import sys
import threading

from env_utils import load_dotenv


REPO_ROOT = Path(__file__).resolve().parent.parent
EDC_ROOT = REPO_ROOT / "edc-log"
EDC_AIT_ROOT = EDC_ROOT / "AIT"
EDC_SCHEMAS_ROOT = EDC_ROOT / "schemas"
MAX_RUN_LOG_LINES = 2000

load_dotenv(REPO_ROOT)


try:
    from agent.defaults import DEFAULT_LLM_MODEL_ID
    from agent.trace import TRACE_PREFIX
except ImportError:
    DEFAULT_LLM_MODEL_ID = "deepseek-v4-flash"
    TRACE_PREFIX = "AGENT_TRACE "


KG_AVAILABLE = False
KG_IMPORT_ERROR = ""
try:
    if EDC_ROOT.is_dir() and str(EDC_ROOT) not in sys.path:
        sys.path.insert(0, str(EDC_ROOT))

    from log_pipeline_agent.agent import LogKgPipelineAgent
    from log_pipeline_agent.backend.server import (
        JOB_STORE as KG_JOB_STORE,
        _graph_summary as kg_graph_summary,
        _planner_request as kg_planner_request,
        _read_artifact as kg_read_artifact,
        _run_legacy_job as kg_run_legacy_job,
        _run_smart_job as kg_run_smart_job,
        _safe_project_path as kg_safe_project_path,
        _set_env_if_present as kg_set_env_if_present,
        _tool_result_payload as kg_tool_result_payload,
    )
    from log_pipeline_agent.config import (
        GRAPH_FUSED_DIR as KG_GRAPH_FUSED_DIR,
        GRAPH_SOURCES_DIR as KG_GRAPH_SOURCES_DIR,
        PROJECT_ROOT as KG_PROJECT_ROOT,
        discover_dataset_specs as discover_kg_dataset_specs,
    )
    from log_pipeline_agent.core.neo4j_admin import clear_neo4j_database
    from log_pipeline_agent.core.planner import SmartPipelinePlanner
    from log_pipeline_agent.core.preflight import PreflightAnalyzer

    KG_AVAILABLE = True
except Exception as exc:  # pragma: no cover - surfaced through /api/kg/health.
    KG_IMPORT_ERROR = str(exc)


KG_INPUT_RULES = (
    {
        "fragment": Path("internal_share/logs/audit_internal_share/audit_internal_share/3.csv"),
        "family": "audit",
        "poi_targets": ("audit_POI.csv",),
        "relation_targets": ("audit_relation.csv",),
        "poi_sources": ("audit_POI.csv",),
        "relation_sources": ("audit_relation.csv",),
    },
    {
        "fragment": Path("intranet_server/logs/audit_internal_server/audit_internal_server/3.csv"),
        "family": "audit",
        "poi_targets": ("audit_POI.csv",),
        "relation_targets": ("audit_relation.csv",),
        "poi_sources": ("audit_POI.csv",),
        "relation_sources": ("audit_relation.csv",),
    },
    {
        "fragment": Path("intranet_server/logs/auth/3.csv"),
        "family": "auth",
        "poi_targets": ("auth_POI.csv",),
        "relation_targets": ("auth_relation.csv",),
        "poi_sources": ("auth_POI.csv",),
        "relation_sources": ("auth_relation.csv",),
    },
    {
        "fragment": Path("inet-firewall/logs-label/dnsmasq/3.csv"),
        "family": "dns",
        "poi_targets": ("dns_POI.csv",),
        "relation_targets": ("dns_relation.csv",),
        "poi_sources": ("dns_POI.csv",),
        "relation_sources": ("dns_relation.csv",),
    },
    {
        "fragment": Path("vpn/logs/openvpn/3.csv"),
        "family": "vpn",
        "poi_targets": ("vpn_POI v2.csv",),
        "relation_targets": ("vpn_relation_aligned_final.csv",),
        "poi_sources": ("openvpn_POI.csv", "vpn_POI v2.csv"),
        "relation_sources": ("openvpn_relation.csv", "vpn_relation_aligned_final.csv"),
    },
    {
        "fragment": Path("intranet_server/logs/apache2/intranet.price.fox.org-access/3.csv"),
        "family": "apache",
        "poi_targets": ("apache_POI.csv",),
        "relation_targets": ("apache_relation.csv",),
        "poi_sources": ("apache_POI.csv",),
        "relation_sources": ("apache_relation.csv",),
    },
    {
        "fragment": Path("intranet_server/logs/apache2/intranet.price.fox.org-error/3.csv"),
        "family": "apache",
        "poi_targets": ("apache_POI.csv",),
        "relation_targets": ("apache_relation.csv",),
        "poi_sources": ("apache_POI.csv",),
        "relation_sources": ("apache_relation.csv",),
    },
)


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
    source_lower = source.lower()
    if "openvpn" in source_lower or "vpn" in source_lower:
        family = "openvpn"
    elif "dnsmasq" in source_lower or "dns" in source_lower:
        family = "dns"
    elif "auth" in source_lower:
        family = "auth"
    elif "apache" in source_lower:
        family = "apache"
    elif "audit" in source_lower:
        family = "audit"
    else:
        return None
    suffix = "POI.csv" if kind == "poi" else "relation.csv"
    path = FrontendHandler.schemas_root / f"{family}_{suffix}"
    if path.is_file():
        return path
    if family == "openvpn":
        fallback = FrontendHandler.schemas_root / f"vpn_{suffix}"
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

    if KG_AVAILABLE:
        sync_parser_outputs_to_edc(output_root, FrontendHandler.schemas_root)

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


def sync_parser_outputs_to_edc(output_root: Path, schemas_root: Path) -> dict:
    output_root = Path(output_root).resolve()
    schemas_root = Path(schemas_root).resolve()
    report = {
        "available": KG_AVAILABLE,
        "edc_root": str(EDC_ROOT),
        "ait_root": str(EDC_AIT_ROOT),
        "schemas_root": str(EDC_SCHEMAS_ROOT),
        "copied_csv": 0,
        "copied_schema": 0,
        "unchanged": 0,
        "missing_inputs": [],
        "datasets": [],
    }
    if not KG_AVAILABLE:
        report["error"] = KG_IMPORT_ERROR
        return report

    for rule in KG_INPUT_RULES:
        fragment = rule["fragment"]
        source_csv = output_root / fragment
        target_csv = EDC_AIT_ROOT / fragment
        dataset_report = {
            "family": rule["family"],
            "source_csv": str(source_csv),
            "target_csv": str(target_csv),
            "csv_copied": False,
            "schemas": [],
            "available": source_csv.is_file() or target_csv.is_file(),
        }
        if source_csv.is_file():
            if _copy_if_changed(source_csv, target_csv):
                report["copied_csv"] += 1
                dataset_report["csv_copied"] = True
            else:
                report["unchanged"] += 1
        elif not target_csv.is_file():
            report["missing_inputs"].append(fragment.as_posix())

        per_source_poi = source_csv.parent / "poi_schema.csv"
        per_source_relation = source_csv.parent / "relation_schema.csv"
        poi_source = per_source_poi if per_source_poi.is_file() else _first_existing(
            schemas_root, rule["poi_sources"]
        )
        relation_source = (
            per_source_relation
            if per_source_relation.is_file()
            else _first_existing(schemas_root, rule["relation_sources"])
        )
        for source_path, targets, kind in (
            (poi_source, rule["poi_targets"], "poi"),
            (relation_source, rule["relation_targets"], "relation"),
        ):
            if not source_path:
                continue
            for target_name in targets:
                target_path = EDC_SCHEMAS_ROOT / target_name
                copied = _copy_if_changed(source_path, target_path)
                if copied:
                    report["copied_schema"] += 1
                else:
                    report["unchanged"] += 1
                dataset_report["schemas"].append(
                    {
                        "kind": kind,
                        "source": str(source_path),
                        "target": str(target_path),
                        "copied": copied,
                    }
                )
        report["datasets"].append(dataset_report)
    return report


def kg_datasets_payload(output_root: Path | None = None, schemas_root: Path | None = None, sync: bool = True) -> dict:
    if not KG_AVAILABLE:
        return {"available": False, "error": KG_IMPORT_ERROR, "datasets": []}
    sync_report = (
        sync_parser_outputs_to_edc(output_root, schemas_root)
        if sync and output_root and schemas_root
        else {"available": True}
    )
    datasets = []
    for spec in discover_kg_dataset_specs():
        datasets.append(
            {
                "name": spec.name,
                "family": spec.family,
                "tag": spec.tag,
                "csv_path": str(spec.csv_path),
                "template2samples_path": str(spec.template2samples_path),
                "pairs_path": str(spec.pairs_path),
                "schema_path": str(spec.schema_path),
                "mapped_pairs_path": str(spec.mapped_pairs_path),
                "params_output_path": str(spec.params_output_path),
                "relation_csv_path": str(spec.relation_csv_path),
                "poi_schema_path": str(spec.poi_schema_path),
            }
        )
    return {
        "available": True,
        "project_root": str(KG_PROJECT_ROOT),
        "ait_root": str(EDC_AIT_ROOT),
        "default_fused_graph_dir": str(KG_GRAPH_FUSED_DIR),
        "default_source_graph_dir": str(KG_GRAPH_SOURCES_DIR),
        "datasets": datasets,
        "sync": sync_report,
    }


def _copy_if_changed(source: Path, target: Path) -> bool:
    source = Path(source)
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        source_stat = source.stat()
        target_stat = target.stat()
        if (
            source_stat.st_size == target_stat.st_size
            and int(source_stat.st_mtime) <= int(target_stat.st_mtime)
        ):
            return False
    shutil.copy2(source, target)
    return True


def _first_existing(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        path = Path(root) / name
        if path.is_file():
            return path
    for name in names:
        path = EDC_SCHEMAS_ROOT / name
        if path.is_file():
            return path
    return None


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
            mock_llm = bool(payload.get("mockLlm", False))
            planner_enabled = bool(payload.get("plannerEnabled", True))
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
            ]
            if write_group_tree:
                command.append("--write_group_tree")
            if preserve_existing:
                command.append("--preserve_existing")
            if mock_llm:
                command.append("--mock_llm")
            if not planner_enabled:
                command.append("--disable_planner")

            env = os.environ.copy()
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
                self.state["message"] = "解析任务已完成。"
                sync_parser_outputs_to_edc(self.output_root, self.schemas_root)
            else:
                self.state["status"] = "failed"
                self.state["message"] = f"解析任务失败，退出码 {returncode}。"

    def _append_log(self, run_id: int, line: str) -> None:
        clean_line = line.replace("\r", "").strip()
        if not clean_line:
            return
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
            if clean_line.startswith(TRACE_PREFIX):
                try:
                    event = json.loads(clean_line[len(TRACE_PREFIX) :])
                    self.state.setdefault("traces", []).append(event)
                    if len(self.state["traces"]) > MAX_RUN_LOG_LINES:
                        self.state["traces"] = self.state["traces"][-MAX_RUN_LOG_LINES:]
                except json.JSONDecodeError:
                    pass

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
    return " ".join(str(part) for part in command)


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
            if parsed.path.startswith("/api/kg/"):
                self._handle_kg_get(parsed)
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
            if parsed.path.startswith("/api/kg/"):
                self._handle_kg_post(parsed)
                return
            self.send_error(404)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def _handle_kg_get(self, parsed) -> None:
        if parsed.path == "/api/kg/health":
            self._send_json({"available": KG_AVAILABLE, "error": KG_IMPORT_ERROR})
            return
        self._ensure_kg_available()
        if parsed.path == "/api/kg/sync":
            self._send_json(sync_parser_outputs_to_edc(self.output_root, self.schemas_root))
            return
        if parsed.path == "/api/kg/datasets":
            query = parse_qs(parsed.query)
            sync = query.get("sync", ["1"])[0] != "0"
            self._send_json(kg_datasets_payload(self.output_root, self.schemas_root, sync=sync))
            return
        if parsed.path.startswith("/api/kg/runs/") and parsed.path.endswith("/events"):
            self._serve_kg_events(parsed.path)
            return
        if parsed.path.startswith("/api/kg/runs/"):
            self._send_json(self._kg_job_payload(parsed.path))
            return
        if parsed.path == "/api/kg/summary":
            query = parse_qs(parsed.query)
            graph_dir = Path(query.get("graph_dir", [str(KG_GRAPH_FUSED_DIR)])[0])
            self._send_json(kg_graph_summary(graph_dir))
            return
        if parsed.path == "/api/kg/artifact":
            query = parse_qs(parsed.query)
            artifact_path = kg_safe_project_path(query.get("path", [""])[0])
            self._send_json(kg_read_artifact(artifact_path))
            return
        self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def _handle_kg_post(self, parsed) -> None:
        self._ensure_kg_available()
        payload = self._read_json_body()
        sync_paths = {"/api/kg/sync", "/api/kg/preflight", "/api/kg/plan", "/api/kg/runs"}
        if parsed.path in sync_paths and payload.get("sync_inputs", True):
            sync_parser_outputs_to_edc(self.output_root, self.schemas_root)

        if parsed.path == "/api/kg/sync":
            self._send_json(sync_parser_outputs_to_edc(self.output_root, self.schemas_root))
            return
        if parsed.path == "/api/kg/preflight":
            request = kg_planner_request(payload)
            report = PreflightAnalyzer().run(request.datasets)
            self._send_json(report.to_dict())
            return
        if parsed.path == "/api/kg/plan":
            request = kg_planner_request(payload)
            preflight = PreflightAnalyzer().run(request.datasets)
            plan = SmartPipelinePlanner().build_plan(request, preflight=preflight)
            self._send_json({"preflight": preflight.to_dict(), "plan": plan.to_dict()})
            return
        if parsed.path == "/api/kg/runs":
            job = KG_JOB_STORE.create()
            mode = str(payload.get("mode", "smart")).lower()
            target = kg_run_legacy_job if mode == "legacy" else kg_run_smart_job
            threading.Thread(target=target, args=(job, payload), daemon=True).start()
            self._send_json(job.to_payload(), status=HTTPStatus.ACCEPTED)
            return
        if parsed.path == "/api/kg/query-artifacts":
            agent = LogKgPipelineAgent()
            result = agent.query_artifacts(
                graph_dir=Path(payload.get("graph_dir") or KG_GRAPH_FUSED_DIR),
                label=str(payload.get("label", "")).strip(),
                predicate=str(payload.get("predicate", "")).strip(),
                contains=str(payload.get("contains", "")).strip(),
                limit=int(payload.get("limit", 20)),
            )
            self._send_json(kg_tool_result_payload(result))
            return
        if parsed.path == "/api/kg/query-neo4j":
            kg_set_env_if_present("NEO4J_URI", payload.get("neo4j_uri"))
            kg_set_env_if_present("NEO4J_USER", payload.get("neo4j_user"))
            kg_set_env_if_present("NEO4J_PASSWORD", payload.get("neo4j_password"))
            kg_set_env_if_present("DEEPSEEK_API_KEY", payload.get("api_key"))
            kg_set_env_if_present("DS_TOKEN", payload.get("api_key"))
            config_path = Path(payload.get("config", ""))
            if not config_path.is_absolute():
                config_path = EDC_ROOT / config_path
            agent = LogKgPipelineAgent()
            result = agent.query_neo4j(
                config_path=config_path,
                question=str(payload.get("question", "")).strip(),
                refresh_schema=_as_bool(payload.get("refresh_schema")),
                max_result_rows=_as_optional_int(payload.get("max_result_rows")),
                max_answer_rows=_as_optional_int(payload.get("max_answer_rows")),
            )
            self._send_json(kg_tool_result_payload(result))
            return
        if parsed.path == "/api/kg/neo4j/clear":
            self._send_json(clear_neo4j_database(payload))
            return
        self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def _serve_kg_events(self, path: str) -> None:
        job_id = path.rstrip("/").split("/")[-2]
        job = KG_JOB_STORE.get(job_id)
        if job is None:
            self._send_json({"error": f"Job not found: {job_id}"}, status=HTTPStatus.NOT_FOUND)
            return

        self.send_response(HTTPStatus.OK)
        self._send_cors_headers()
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        index = 0
        try:
            while True:
                with job.condition:
                    if index >= len(job.events) and job.status == "running":
                        job.condition.wait(timeout=15)
                    pending = job.events[index:]
                    index = len(job.events)
                    finished = job.status != "running" and not pending
                for event in pending:
                    payload = json.dumps(event, ensure_ascii=False)
                    self.wfile.write(f"id: {event['id']}\n".encode("utf-8"))
                    self.wfile.write(f"event: {event['type']}\n".encode("utf-8"))
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                if finished:
                    break
                if not pending:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            self.close_connection = True

    def _kg_job_payload(self, path: str) -> dict:
        job_id = path.rstrip("/").split("/")[-1]
        job = KG_JOB_STORE.get(job_id)
        if job is None:
            raise FileNotFoundError(f"Job not found: {job_id}")
        payload = job.to_payload()
        payload["events"] = list(job.events)
        return payload

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

    @staticmethod
    def _ensure_kg_available() -> None:
        if not KG_AVAILABLE:
            raise RuntimeError(f"知识图谱模块不可用: {KG_IMPORT_ERROR}")

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")


def _as_bool(raw) -> bool:
    return bool(raw) if isinstance(raw, bool) else str(raw).lower() in {"1", "true", "yes", "on"}


def _as_optional_int(raw) -> int | None:
    if raw in (None, ""):
        return None
    return int(raw)


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
    if KG_AVAILABLE:
        sync_parser_outputs_to_edc(FrontendHandler.output_root, FrontendHandler.schemas_root)
    server = ThreadingHTTPServer((args.host, args.port), FrontendHandler)
    print(f"Backend API server: http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
