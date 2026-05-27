import ast
import json
import re

from agent import compat

compat.ensure_parser_path()

from deepseek_client import DeepSeekClient


class HeuristicTemplateClient:
    """Small offline client used only for local smoke tests."""

    def __init__(self, model="mock-llm"):
        self.model = model

    def generate(self, messages, max_tokens=1024, temperature=0.0, **kwargs):
        if _is_group_planner_request(messages):
            return json.dumps(
                {
                    "strategy": "memory_first_sampling_reflection",
                    "similarity": "jaccard",
                    "use_memory": True,
                    "use_reflection": True,
                    "tools": [
                        "memory_lookup",
                        "select_representative_logs",
                        "llm_generate_template",
                        "validate_regex",
                        "reflection_retry",
                        "memory_add",
                    ],
                    "reason": "离线烟测采用默认事件组策略。",
                },
                ensure_ascii=False,
            )
        if _is_planner_request(messages):
            return json.dumps(
                {
                    "actions": [
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
                            "reason": "为该日志源准备 POI 字段库和 relation 库。",
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
                            "reason": "写入 CSV、schema 副本和运行汇总。",
                        },
                    ],
                    "notes": "离线烟测使用确定性计划。",
                }
            )
        if _is_schema_request(messages):
            return json.dumps(_heuristic_schema(messages), ensure_ascii=False)
        logs = _extract_logs_from_messages(messages)
        template = _generalize_logs(logs)
        return json.dumps({"template": template})


def create_llm_client(config):
    if config.mock_llm:
        return HeuristicTemplateClient()
    return DeepSeekClient(
        model=config.model,
        api_key=config.api_key,
        api_key_env=config.api_key_env,
        base_url=config.api_base,
        timeout=config.api_timeout,
        max_retries=config.api_retries,
        temperature=config.temperature,
        reasoning_effort=config.reasoning_effort,
        thinking_enabled=config.thinking_enabled,
    )


def generate_log_regex(template_engine, log_list, records=False, do_sample=False):
    return template_engine.generate_log_template_using_pipeline(
        log_list=log_list,
        dic=records,
        do_sample=do_sample,
        max_new_tokens=template_engine.max_new_tokens,
    )


def _extract_logs_from_messages(messages):
    for message in reversed(messages):
        content = message.get("content", "")
        match = re.search(r"Log list:\s*(\[.*\])", content, flags=re.DOTALL)
        if not match:
            continue
        try:
            parsed = ast.literal_eval(match.group(1))
        except (SyntaxError, ValueError):
            continue
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    return []


def _generalize_logs(logs):
    if not logs:
        return ""
    tokenized = [log.split() for log in logs]
    max_len = max(len(tokens) for tokens in tokenized)
    template_tokens = []
    for index in range(max_len):
        values = [tokens[index] if index < len(tokens) else None for tokens in tokenized]
        first = values[0]
        if first is not None and all(value == first for value in values):
            template_tokens.append(first)
        else:
            template_tokens.append("<*>")
    return " ".join(template_tokens)


def generate_json(pipeline, messages, max_tokens=2048, temperature=0.0):
    response = pipeline.generate(
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
        response_format_json=True,
    )
    return parse_json_response(response)


def parse_json_response(response_text):
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", response_text, flags=re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _is_planner_request(messages):
    return any(
        "agent execution planner" in message.get("content", "").lower()
        for message in messages
    )


def _is_group_planner_request(messages):
    return any(
        "group parsing planner" in message.get("content", "").lower()
        for message in messages
    )


def _is_schema_request(messages):
    return any(
        "poi/relation schema designer" in message.get("content", "").lower()
        for message in messages
    )


def _heuristic_schema(messages):
    text = "\n".join(message.get("content", "") for message in messages).lower()
    if "openvpn" in text or "tls" in text or "verify" in text:
        schema_type = "openvpn"
        poi_fields = [
            ["host", "Local VPN host or collector that emitted the log."],
            ["program", "VPN service component; use openvpn when absent."],
            ["event_type", "Canonical VPN event category such as tls_reset, certificate_verify, connection_state, or auth_result."],
            ["event_action", "Normalized action verb from the VPN template."],
            ["user", "VPN user identity when present in the peer token."],
            ["src_ip", "Remote VPN peer IP address."],
            ["src_port", "Remote VPN peer port."],
            ["certificate_cn", "Certificate common name when present."],
            ["tls_state", "TLS lifecycle or verification state when present."],
            ["outcome", "Normalized success/failure/unknown result."],
        ]
        relations = [
            {
                "subject_type": "User",
                "subject_id_source": "user",
                "predicate": "CONNECTS_FROM",
                "object_type": "IP",
                "object_id_source": "src_ip",
                "edge_properties": "src_port,event_type,event_action,outcome",
                "condition": "user not null AND src_ip not null",
            },
            {
                "subject_type": "Program",
                "subject_id_source": "program",
                "predicate": "RUNS_ON",
                "object_type": "Host",
                "object_id_source": "host",
                "edge_properties": "event_type,event_action,outcome",
                "condition": "program not null AND host not null",
            },
            {
                "subject_type": "User",
                "subject_id_source": "user",
                "predicate": "PRESENTS_CERTIFICATE",
                "object_type": "Certificate",
                "object_id_source": "certificate_cn",
                "edge_properties": "tls_state,event_type,outcome",
                "condition": "user not null AND certificate_cn not null",
            },
        ]
    else:
        schema_type = "generated_log"
        poi_fields = [
            ["host", "Hostname/device that emitted the log."],
            ["program", "Emitting application or service name."],
            ["event_type", "Canonical event category inferred from the template."],
            ["event_action", "Normalized action verb inferred from the template."],
            ["actor", "Primary actor entity when available."],
            ["target", "Primary target entity when available."],
            ["object", "Main object acted on by the event."],
            ["outcome", "Normalized success/failure/unknown result."],
        ]
        relations = [
            {
                "subject_type": "Program",
                "subject_id_source": "program",
                "predicate": "RUNS_ON",
                "object_type": "Host",
                "object_id_source": "host",
                "edge_properties": "event_type,event_action,outcome",
                "condition": "program not null AND host not null",
            },
            {
                "subject_type": "Actor",
                "subject_id_source": "actor",
                "predicate": "ACTS_ON",
                "object_type": "Object",
                "object_id_source": "object",
                "edge_properties": "target,event_type,event_action,outcome",
                "condition": "actor not null AND object not null",
            },
        ]
    return {
        "schema_type": schema_type,
        "poi_fields": [
            {"field": field, "description": description}
            for field, description in poi_fields
        ],
        "relations": relations,
        "alignment_notes": "Generated by offline heuristic for smoke testing.",
    }
