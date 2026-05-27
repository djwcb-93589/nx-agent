from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import csv
import json
import os
from pathlib import Path
import threading
import traceback
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from uuid import uuid4

from ..agent import AgentRunOptions, LogKgPipelineAgent
from ..config import GRAPH_FUSED_DIR, GRAPH_SOURCES_DIR, PROJECT_ROOT, discover_dataset_specs
from ..core.executor import DagPipelineExecutor
from ..core.memory import RunMemory
from ..core.neo4j_admin import clear_neo4j_database
from ..core.planner import PlannerRequest, SmartPipelinePlanner
from ..core.preflight import PreflightAnalyzer
from ..tools import ToolResult
from env_utils import get_env, load_dotenv


DEFAULT_FUSED_GRAPH_DIR = GRAPH_FUSED_DIR
DEFAULT_SOURCE_GRAPH_DIR = GRAPH_SOURCES_DIR
load_dotenv(PROJECT_ROOT)


@dataclass
class JobState:
    job_id: str
    status: str = "running"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    events: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str = ""
    condition: threading.Condition = field(default_factory=threading.Condition)

    def add_event(self, event_type: str, payload: dict[str, Any]) -> None:
        with self.condition:
            event = {
                "id": len(self.events) + 1,
                "type": event_type,
                "time": datetime.now().isoformat(timespec="seconds"),
                "payload": payload,
            }
            self.events.append(event)
            self.updated_at = event["time"]
            self.condition.notify_all()

    def to_payload(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "event_count": len(self.events),
            "result": self.result,
            "error": self.error,
        }


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, JobState] = {}
        self._lock = threading.Lock()

    def create(self) -> JobState:
        job = JobState(job_id=uuid4().hex[:12])
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> JobState | None:
        with self._lock:
            return self._jobs.get(job_id)


JOB_STORE = JobStore()


def _planner_request(payload: dict[str, Any]) -> PlannerRequest:
    payload = _sanitize_runtime_secret_payload(payload)
    return PlannerRequest(
        task=str(payload.get("task", "")).strip(),
        datasets=tuple(str(item) for item in payload.get("datasets", []) if str(item).strip()),
        force=_as_bool(payload.get("force")),
        skip_llm_steps=_as_optional_bool(payload.get("skip_llm_steps")),
        skip_param_extraction=_as_optional_bool(payload.get("skip_param_extraction")),
        skip_kg_build=_as_optional_bool(payload.get("skip_kg_build")),
        write_neo4j=_as_bool(payload.get("write_neo4j")),
        limit_rows=_as_optional_int(payload.get("limit_rows")),
        api_key=str(payload.get("api_key", "")).strip(),
        fused_graph_dir=str(payload.get("fused_graph_dir", "")).strip(),
        per_dataset_graph_dir=str(payload.get("per_dataset_graph_dir", "")).strip(),
        neo4j_uri=_payload_or_env(payload, "neo4j_uri", "NEO4J_URI"),
        neo4j_user=_payload_or_env(payload, "neo4j_user", "NEO4J_USER"),
        neo4j_password=_payload_or_env_ref(payload, "neo4j_password", "NEO4J_PASSWORD"),
        neo4j_database=_payload_or_env(payload, "neo4j_database", "NEO4J_DATABASE", "neo4j"),
        max_workers=int(payload.get("max_workers", 1) or 1),
    )


def _options_from_payload(payload: dict[str, Any]) -> AgentRunOptions:
    payload = _sanitize_runtime_secret_payload(payload)
    force = _as_bool(payload.get("force"))
    return AgentRunOptions(
        dataset_names=tuple(str(item) for item in payload.get("datasets", []) if str(item).strip()),
        force_template2samples=force or _as_bool(payload.get("force_template2samples")),
        force_pairs=force or _as_bool(payload.get("force_pairs")),
        force_schema=force or _as_bool(payload.get("force_schema")),
        force_mapped_pairs=force or _as_bool(payload.get("force_mapped_pairs")),
        force_params=force or _as_bool(payload.get("force_params")),
        skip_llm_steps=_as_bool(payload.get("skip_llm_steps")),
        skip_param_extraction=_as_bool(payload.get("skip_param_extraction")),
        skip_kg_build=_as_bool(payload.get("skip_kg_build")),
        api_key=str(payload.get("api_key", "")).strip(),
        limit_rows=_as_optional_int(payload.get("limit_rows")),
        per_dataset_graph_dir=Path(payload.get("per_dataset_graph_dir") or DEFAULT_SOURCE_GRAPH_DIR),
        fused_graph_dir=Path(payload.get("fused_graph_dir") or DEFAULT_FUSED_GRAPH_DIR),
        write_neo4j=_as_bool(payload.get("write_neo4j")),
        neo4j_uri=_payload_or_env(payload, "neo4j_uri", "NEO4J_URI"),
        neo4j_user=_payload_or_env(payload, "neo4j_user", "NEO4J_USER"),
        neo4j_password=_payload_or_env_ref(payload, "neo4j_password", "NEO4J_PASSWORD"),
        neo4j_database=_payload_or_env(payload, "neo4j_database", "NEO4J_DATABASE", "neo4j"),
    )


def _run_smart_job(job: JobState, payload: dict[str, Any]) -> None:
    try:
        specs = discover_dataset_specs()
        request = _planner_request(payload)
        preflight = PreflightAnalyzer(specs).run(request.datasets)
        planner = SmartPipelinePlanner(specs)
        plan = planner.build_plan(request, preflight=preflight)
        options = planner.options_from_plan(plan)
        memory = RunMemory()
        memory.write_json("preflight.json", preflight.to_dict())

        def progress(event_type: str, event_payload: dict[str, Any]) -> None:
            job.add_event(event_type, event_payload)

        job.add_event("preflight_finished", preflight.to_dict())
        job.add_event("plan_created", plan.to_dict())
        outcome = DagPipelineExecutor(specs).execute(
            plan,
            options,
            progress_callback=progress,
            memory=memory,
        )
        job.result = outcome
        job.status = "completed"
        job.add_event("job_completed", outcome)
    except Exception as exc:
        job.error = f"{exc}\n{traceback.format_exc()}"
        job.status = "failed"
        job.add_event("job_failed", {"message": str(exc), "traceback": traceback.format_exc()})


def _run_legacy_job(job: JobState, payload: dict[str, Any]) -> None:
    agent = LogKgPipelineAgent()
    options = _options_from_payload(payload)

    def progress(event_type: str, event_payload: dict[str, Any]) -> None:
        job.add_event(event_type, event_payload)

    try:
        outcome = agent.run(options, progress_callback=progress)
        job.result = {
            "datasets": outcome.get("datasets", []),
            "results": [_tool_result_payload(item) for item in outcome.get("results", [])],
        }
        job.status = "completed"
        job.add_event("job_completed", job.result)
    except Exception as exc:
        job.error = f"{exc}\n{traceback.format_exc()}"
        job.status = "failed"
        job.add_event("job_failed", {"message": str(exc), "traceback": traceback.format_exc()})


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "LogPipelineAgentAPI/2.0"

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/health":
                self._send_json({"status": "ok", "time": datetime.now().isoformat(timespec="seconds")})
            elif path == "/api/datasets":
                self._send_json(self._datasets_payload())
            elif path.startswith("/api/runs/") and path.endswith("/events"):
                self._serve_events(path)
            elif path.startswith("/api/runs/"):
                self._send_json(self._job_payload(path))
            elif path == "/api/summary":
                query = parse_qs(parsed.query)
                graph_dir = Path(query.get("graph_dir", [str(DEFAULT_FUSED_GRAPH_DIR)])[0])
                self._send_json(_graph_summary(graph_dir))
            elif path == "/api/artifact":
                query = parse_qs(parsed.query)
                artifact_path = _safe_project_path(query.get("path", [""])[0])
                self._send_json(_read_artifact(artifact_path))
            else:
                self._send_error(HTTPStatus.NOT_FOUND, "Not found")
        except Exception as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            payload = self._read_json_body()
            if parsed.path == "/api/preflight":
                request = _planner_request(payload)
                report = PreflightAnalyzer().run(request.datasets)
                self._send_json(report.to_dict())
            elif parsed.path == "/api/plan":
                request = _planner_request(payload)
                preflight = PreflightAnalyzer().run(request.datasets)
                plan = SmartPipelinePlanner().build_plan(request, preflight=preflight)
                self._send_json({"preflight": preflight.to_dict(), "plan": plan.to_dict()})
            elif parsed.path == "/api/runs":
                job = JOB_STORE.create()
                mode = str(payload.get("mode", "smart")).lower()
                target = _run_legacy_job if mode == "legacy" else _run_smart_job
                threading.Thread(target=target, args=(job, payload), daemon=True).start()
                self._send_json(job.to_payload(), status=HTTPStatus.ACCEPTED)
            elif parsed.path == "/api/query-artifacts":
                agent = LogKgPipelineAgent()
                result = agent.query_artifacts(
                    graph_dir=Path(payload.get("graph_dir") or DEFAULT_FUSED_GRAPH_DIR),
                    label=str(payload.get("label", "")).strip(),
                    predicate=str(payload.get("predicate", "")).strip(),
                    contains=str(payload.get("contains", "")).strip(),
                    limit=int(payload.get("limit", 20)),
                )
                self._send_json(_tool_result_payload(result))
            elif parsed.path == "/api/query-neo4j":
                _set_env_if_present("NEO4J_URI", payload.get("neo4j_uri"))
                _set_env_if_present("NEO4J_USER", payload.get("neo4j_user"))
                _set_env_if_present("NEO4J_PASSWORD", payload.get("neo4j_password"))
                _set_env_if_present("DEEPSEEK_API_KEY", payload.get("api_key"))
                _set_env_if_present("DS_TOKEN", payload.get("api_key"))
                agent = LogKgPipelineAgent()
                result = agent.query_neo4j(
                    config_path=Path(payload.get("config", "")),
                    question=str(payload.get("question", "")).strip(),
                    refresh_schema=_as_bool(payload.get("refresh_schema")),
                    max_result_rows=_as_optional_int(payload.get("max_result_rows")),
                    max_answer_rows=_as_optional_int(payload.get("max_answer_rows")),
                )
                self._send_json(_tool_result_payload(result))
            elif parsed.path == "/api/neo4j/clear":
                self._send_json(clear_neo4j_database(payload))
            else:
                self._send_error(HTTPStatus.NOT_FOUND, "Not found")
        except Exception as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))

    def log_message(self, format: str, *args: Any) -> None:
        print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), format % args))

    def _datasets_payload(self) -> dict[str, Any]:
        datasets = []
        for spec in discover_dataset_specs():
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
                }
            )
        return {
            "project_root": str(PROJECT_ROOT),
            "default_fused_graph_dir": str(DEFAULT_FUSED_GRAPH_DIR),
            "default_source_graph_dir": str(DEFAULT_SOURCE_GRAPH_DIR),
            "datasets": datasets,
        }

    def _job_payload(self, path: str) -> dict[str, Any]:
        job_id = path.rstrip("/").split("/")[-1]
        job = JOB_STORE.get(job_id)
        if job is None:
            raise FileNotFoundError(f"Job not found: {job_id}")
        return job.to_payload()

    def _serve_events(self, path: str) -> None:
        job_id = path.rstrip("/").split("/")[-2]
        job = JOB_STORE.get(job_id)
        if job is None:
            self._send_error(HTTPStatus.NOT_FOUND, f"Job not found: {job_id}")
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
                    self._write_sse(event)
                if finished:
                    break
                if not pending:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            self.close_connection = True

    def _write_sse(self, event: dict[str, Any]) -> None:
        payload = json.dumps(event, ensure_ascii=False)
        self.wfile.write(f"id: {event['id']}\n".encode("utf-8"))
        self.wfile.write(f"event: {event['type']}\n".encode("utf-8"))
        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
        self.wfile.flush()

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json({"error": message}, status=status)

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")


def _as_bool(raw: Any) -> bool:
    return bool(raw) if isinstance(raw, bool) else str(raw).lower() in {"1", "true", "yes", "on"}


def _sanitize_runtime_secret_payload(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(payload)
    api_key = str(sanitized.get("api_key", "") or "").strip()
    if api_key:
        os.environ["DEEPSEEK_API_KEY"] = api_key
        os.environ["DS_TOKEN"] = api_key
        sanitized["api_key"] = ""

    neo4j_password = str(sanitized.get("neo4j_password", "") or "")
    if neo4j_password:
        os.environ["NEO4J_PASSWORD"] = neo4j_password
        sanitized["neo4j_password"] = "${NEO4J_PASSWORD}"
    return sanitized


def _payload_or_env(
    payload: dict[str, Any],
    payload_key: str,
    env_key: str,
    default: str = "",
) -> str:
    value = str(payload.get(payload_key, "") or "").strip()
    return value or get_env(env_key, default)


def _payload_or_env_ref(payload: dict[str, Any], payload_key: str, env_key: str) -> str:
    value = str(payload.get(payload_key, "") or "").strip()
    if value:
        return value
    return f"${{{env_key}}}" if get_env(env_key) else ""


def _as_optional_bool(raw: Any) -> bool | None:
    if raw is None or raw == "":
        return None
    return _as_bool(raw)


def _as_optional_int(raw: Any) -> int | None:
    if raw in (None, ""):
        return None
    return int(raw)


def _set_env_if_present(name: str, value: Any) -> None:
    text = str(value or "").strip()
    if text:
        os.environ[name] = text


def _tool_result_payload(result: ToolResult) -> dict[str, Any]:
    return {
        "tool": result.tool,
        "message": result.message,
        "outputs": result.outputs,
        "metrics": result.metrics,
        "skipped": result.skipped,
    }


def _safe_project_path(raw_path: str) -> Path:
    path = Path(unquote(raw_path)).resolve()
    root = PROJECT_ROOT.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError("Only project-local artifacts can be read") from exc
    return path


def _read_artifact(path: Path, max_bytes: int = 200_000) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {path}")
    if path.is_dir():
        return {
            "path": str(path),
            "kind": "directory",
            "entries": [item.name for item in sorted(path.iterdir())[:200]],
            "truncated": False,
        }

    raw = path.read_bytes()
    truncated = len(raw) > max_bytes
    content = raw[:max_bytes].decode("utf-8-sig", errors="replace")
    return {
        "path": str(path),
        "kind": "file",
        "content": content,
        "size_bytes": len(raw),
        "truncated": truncated,
    }


def _count_csv(path: Path, column: str | None = None) -> tuple[int, dict[str, int]]:
    if not path.exists():
        return 0, {}

    total = 0
    counts: dict[str, int] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            total += 1
            if column:
                value = row.get(column, "")
                if value:
                    counts[value] = counts.get(value, 0) + 1
    return total, dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:12])


def _graph_summary(graph_dir: Path) -> dict[str, Any]:
    graph_dir = graph_dir.resolve()
    nodes_path = graph_dir / "nodes.csv"
    edges_path = graph_dir / "edges.csv"
    node_count, labels = _count_csv(nodes_path, "label")
    edge_count, predicates = _count_csv(edges_path, "predicate")
    return {
        "graph_dir": str(graph_dir),
        "nodes_csv": str(nodes_path),
        "edges_csv": str(edges_path),
        "node_count": node_count,
        "edge_count": edge_count,
        "labels": labels,
        "predicates": predicates,
        "exists": nodes_path.exists() or edges_path.exists(),
    }


def run_server(host: str = "127.0.0.1", port: int = 8787) -> None:
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print(f"Log pipeline API: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping API...")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Backend API for the log KG pipeline agent.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
