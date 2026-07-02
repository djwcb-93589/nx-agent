import json

from agent.tools import llm_tools


DEFAULT_PLAN = [
    {
        "tool": "read_raw_logs",
        "reason": "读取原始日志作为后续处理输入。",
    },
    {
        "tool": "preprocess_logs",
        "reason": "抽取时间戳并保留原始内容映射。",
    },
    {
        "tool": "ensure_schema",
        "reason": "为日志源准备 POI 字段库和 relation 库。",
    },
    {
        "tool": "build_deep_group_tree",
        "reason": "构建深度分组树并得到候选事件组。",
    },
    {
        "tool": "parse_groups_with_memory_reflection",
        "reason": "按组执行记忆命中、代表日志采样、模板生成和反思修正。",
    },
    {
        "tool": "write_outputs",
        "reason": "写入解析结果、schema 副本和运行汇总。",
    },
]

VALID_TOOLS = {item["tool"] for item in DEFAULT_PLAN}


class DeepSeekPlanner:
    def __init__(self, pipeline, enabled=True, max_tokens=2048):
        self.pipeline = pipeline
        self.enabled = enabled
        self.max_tokens = max_tokens

    def plan_source(self, source_name, raw_preview, schema_hint, config):
        if not self.enabled:
            return {"actions": DEFAULT_PLAN, "notes": "Planner disabled; using default plan."}

        messages = [
            {
                "role": "system",
                "content": (
                    "You are an agent execution planner for a security log parsing "
                    "and knowledge-graph schema pipeline. Select tool actions from "
                    "the provided tool catalog. Return valid JSON only. Do not reveal "
                    "hidden reasoning; provide concise auditable reasons."
                ),
            },
            {
                "role": "user",
                "content": {
                    "source": source_name,
                    "raw_preview": raw_preview,
                    "schema_hint": schema_hint,
                    "tool_catalog": [
                        "read_raw_logs",
                        "preprocess_logs",
                        "ensure_schema",
                        "build_deep_group_tree",
                        "parse_groups_with_memory_reflection",
                        "write_outputs",
                    ],
                    "requirements": [
                        "Use POI/relation schema before template parsing is finalized.",
                        "Use memory and reflection during group parsing.",
                        "Write output CSV files compatible with LibreLog.",
                        "Return actions as an ordered array of objects with tool and reason.",
                    ],
                    "runtime_config": {
                        "sample": config.sample,
                        "similarity": config.similarity,
                        "self_reflection": config.do_self_reflection,
                    },
                },
            },
        ]
        messages[1]["content"] = json.dumps(messages[1]["content"], ensure_ascii=False)
        try:
            payload = llm_tools.generate_json(
                self.pipeline,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=0.0,
            )
            if isinstance(payload, list):
                payload = {"actions": payload}
            if not isinstance(payload, dict):
                raise TypeError(f"Planner response must be an object or action array, got {type(payload).__name__}")
            actions = normalize_actions(payload.get("actions") or [])
            if not actions:
                raise ValueError("Planner returned no valid actions.")
            if not is_order_valid(actions):
                raise ValueError("Planner returned an invalid dependency order.")
            return {
                "actions": actions,
                "notes": str(payload.get("notes") or "GLM planner generated the plan."),
            }
        except Exception as exc:
            return {
                "actions": DEFAULT_PLAN,
                "notes": f"Planner fallback used: {exc}",
            }

    def plan_group(
        self,
        source_name,
        event_id,
        sample_logs,
        group_size,
        memory_size,
        schema_info,
        config,
    ):
        default_strategy = {
            "strategy": "memory_first_sampling_reflection",
            "similarity": config.similarity,
            "use_memory": True,
            "use_reflection": config.do_self_reflection == "True",
            "tools": [
                "memory_lookup",
                "select_representative_logs",
                "llm_generate_template",
                "validate_regex",
                "reflection_retry",
                "memory_add",
            ],
            "reason": "Default group strategy preserves LibreLog behavior.",
        }
        if not self.enabled:
            return default_strategy
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a group parsing planner inside a log parsing agent. "
                    "Choose an auditable tool strategy for one event group. Return "
                    "valid JSON only and do not reveal hidden reasoning."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "source": source_name,
                        "event_id": event_id,
                        "group_size": group_size,
                        "sample_logs": sample_logs,
                        "regex_memory_size": memory_size,
                        "schema_info": schema_info,
                        "available_tools": [
                            "memory_lookup",
                            "select_representative_logs",
                            "llm_generate_template",
                            "validate_regex",
                            "reflection_retry",
                            "memory_add",
                        ],
                        "allowed_similarity": ["jaccard", "cosine", "random"],
                        "required_json_schema": {
                            "strategy": "short_strategy_name",
                            "similarity": "jaccard|cosine|random",
                            "use_memory": True,
                            "use_reflection": True,
                            "tools": ["ordered tool names"],
                            "reason": "concise audit reason",
                        },
                    },
                    ensure_ascii=False,
                ),
            },
        ]
        try:
            payload = llm_tools.generate_json(
                self.pipeline,
                messages=messages,
                max_tokens=1024,
                temperature=0.0,
            )
            similarity = str(payload.get("similarity") or config.similarity).strip()
            if similarity not in {"jaccard", "cosine", "random"}:
                similarity = config.similarity
            tools = [
                str(tool)
                for tool in (payload.get("tools") or default_strategy["tools"])
                if str(tool)
                in {
                    "memory_lookup",
                    "select_representative_logs",
                    "llm_generate_template",
                    "validate_regex",
                    "reflection_retry",
                    "memory_add",
                }
            ]
            return {
                "strategy": str(payload.get("strategy") or default_strategy["strategy"]),
                "similarity": similarity,
                "use_memory": bool(payload.get("use_memory", True)),
                "use_reflection": bool(payload.get("use_reflection", True)),
                "tools": tools or default_strategy["tools"],
                "reason": str(payload.get("reason") or default_strategy["reason"]),
            }
        except Exception as exc:
            fallback = dict(default_strategy)
            fallback["reason"] = f"Group planner fallback used: {exc}"
            return fallback


def normalize_actions(actions):
    normalized = []
    seen = set()
    for item in actions:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool") or "").strip()
        if tool not in VALID_TOOLS or tool in seen:
            continue
        normalized.append(
            {
                "tool": tool,
                "reason": str(item.get("reason") or "").strip(),
            }
        )
        seen.add(tool)

    for required in DEFAULT_PLAN:
        if required["tool"] not in seen:
            normalized.append(required)
    return normalized


def is_order_valid(actions):
    order = [item["tool"] for item in actions]
    required_order = [item["tool"] for item in DEFAULT_PLAN]
    positions = {tool: order.index(tool) for tool in order}
    return all(
        positions.get(required_order[index], -1)
        < positions.get(required_order[index + 1], 10**9)
        for index in range(len(required_order) - 1)
    )
