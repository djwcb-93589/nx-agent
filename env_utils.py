from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable


_LOADED_PATHS: set[Path] = set()


def load_dotenv(start: Path | None = None, *, override: bool = False) -> list[Path]:
    """Load .env files without adding a runtime dependency."""
    loaded: list[Path] = []
    for path in _candidate_env_paths(start):
        if path in _LOADED_PATHS or not path.is_file():
            continue
        _load_env_file(path, override=override)
        _LOADED_PATHS.add(path)
        loaded.append(path)
    return loaded


def get_env(name: str, default: str = "", *, aliases: Iterable[str] = ()) -> str:
    load_dotenv()
    for key in (name, *aliases):
        value = os.getenv(key)
        if value not in (None, ""):
            value = _expand_env_reference(value)
            if not value:
                continue
            return value
    return default


def get_env_int(name: str, default: int, *, aliases: Iterable[str] = ()) -> int:
    value = get_env(name, "", aliases=aliases)
    return int(value) if value else default


def get_env_bool(name: str, default: bool = False, *, aliases: Iterable[str] = ()) -> bool:
    value = get_env(name, "", aliases=aliases)
    if not value:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_env_value(value: Any, default: str = "") -> Any:
    load_dotenv()
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("${") and text.endswith("}"):
            return os.getenv(text[2:-1], default)
    return value


def _candidate_env_paths(start: Path | None = None) -> list[Path]:
    roots: list[Path] = []
    if start is not None:
        roots.append(Path(start).resolve())
    roots.extend([Path.cwd().resolve(), Path(__file__).resolve().parent])

    paths: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        for current in (root, *root.parents):
            candidate = current / ".env"
            if candidate not in seen:
                seen.add(candidate)
                paths.append(candidate)
    return paths


def _load_env_file(path: Path, *, override: bool) -> None:
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or (not override and key in os.environ):
            continue
        os.environ[key] = _expand_env_reference(_clean_value(value))


def _clean_value(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1]
    return text.replace(r"\n", "\n").replace(r"\"", '"').replace(r"\'", "'")


def _expand_env_reference(value: str) -> str:
    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        return os.getenv(text[2:-1], "")
    return value
