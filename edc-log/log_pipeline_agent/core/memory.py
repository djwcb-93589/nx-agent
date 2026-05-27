from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any

from ..config import PROJECT_ROOT


class RunMemory:
    def __init__(self, root: Path | None = None, run_id: str | None = None) -> None:
        self.root = root or (PROJECT_ROOT / "log_pipeline_agent" / "runs")
        self.run_id = run_id or datetime.now().strftime("run_%Y%m%d_%H%M%S")
        self.run_dir = self.root / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, name: str, payload: Any) -> Path:
        path = self.run_dir / name
        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
            file.write("\n")
        return path

    def append_event(self, event_type: str, payload: dict[str, Any]) -> None:
        event = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "type": event_type,
            "payload": payload,
        }
        with (self.run_dir / "events.jsonl").open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")

    def write_summary(self, lines: list[str]) -> Path:
        path = self.run_dir / "summary.md"
        with path.open("w", encoding="utf-8") as file:
            file.write("\n".join(lines).rstrip() + "\n")
        return path
