from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from agent.defaults import DEFAULT_LLM_API_KEY, DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL_ID


@dataclass
class AgentConfig:
    project: str = "all"
    model: str = DEFAULT_LLM_MODEL_ID
    sample: int = 3
    similarity: str = "jaccard"
    do_self_reflection: str = "True"
    api_key: str | None = DEFAULT_LLM_API_KEY
    api_key_env: str = ""
    api_base: str = DEFAULT_LLM_BASE_URL
    api_timeout: int = 120
    api_retries: int = 5
    reasoning_effort: str = "high"
    thinking_enabled: bool = True
    temperature: float = 0.1
    max_new_tokens: int = 1024
    input_dir: str = "full_dataset"
    output_dir: str = "result_deepseek"
    schemas_dir: str = "schemas"
    write_group_tree: bool = False
    overwrite: bool = True
    mock_llm: bool = False
    planner_enabled: bool = True


@dataclass
class SourceRunResult:
    source: str
    output_dir: Path
    result_file: Path
    total_time: timedelta
    llm_parsing_time: float
    grouping_time: float
    regex_matching_time: float
    event_count: str
    line_count: int
    group_count: int
    tree: dict[str, Any] | None = None


@dataclass
class AgentRunResult:
    input_root: Path
    output_root: Path
    sources: list[SourceRunResult] = field(default_factory=list)
