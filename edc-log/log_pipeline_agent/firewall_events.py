from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Iterable
import csv
import json
import re


EVENTS_FILENAME = "customer_events.json"
VALIDATION_FILENAME = "customer_event_validation.json"
REJECTED_FILENAME = "customer_events_rejected.jsonl"

ACTION_LABELS = {
    "add": "添加",
    "set": "修改",
    "edit": "修改",
    "modify": "修改",
    "del": "删除",
    "delete": "删除",
    "show": "显示",
    "clear": "清空",
    "startup": "恢复",
    "bulk_load": "批量加载",
    "login": "登录",
    "logout": "退出",
    "leave": "离开",
}

POLICY_LABELS = {
    "permit": "允许",
    "permit_nat": "允许",
    "deny": "禁止",
    "proxy": "代理",
}

MAC_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def export_customer_events(
    *,
    params_csv: Path,
    output_dirs: Iterable[Path],
    schema_path: Path,
    asset_path: Path,
    device_path: Path,
    source_name: str,
) -> dict[str, Any]:
    schema = _load_json(schema_path)
    assets = _load_csv_index(asset_path, "src_ip")
    devices = _load_csv_index(device_path, "device_name", casefold=True)
    rows = _read_csv(params_csv)
    payload = build_customer_events(
        rows,
        schema=schema,
        assets=assets,
        devices=devices,
        source_name=source_name,
    )

    written = []
    for output_dir in _unique_paths(output_dirs):
        output_dir.mkdir(parents=True, exist_ok=True)
        events_path = output_dir / EVENTS_FILENAME
        validation_path = output_dir / VALIDATION_FILENAME
        rejected_path = output_dir / REJECTED_FILENAME
        _write_json(events_path, payload["events"])
        _write_json(validation_path, payload["report"])
        with rejected_path.open("w", encoding="utf-8", newline="\n") as file:
            for item in payload["rejected"]:
                file.write(json.dumps(item, ensure_ascii=False) + "\n")
        written.append(
            {
                "events": str(events_path.resolve()),
                "validation": str(validation_path.resolve()),
                "rejected": str(rejected_path.resolve()),
            }
        )

    return {
        **payload,
        "written": written,
    }


def build_customer_events(
    rows: list[dict[str, str]],
    *,
    schema: dict[str, Any],
    assets: dict[str, dict[str, str]],
    devices: dict[str, dict[str, str]],
    source_name: str,
) -> dict[str, Any]:
    events = []
    rejected = []
    warnings = []
    rule_state: dict[tuple[str, str], dict[str, str]] = {}
    type_counts: dict[str, int] = {}

    indexed_rows = [
        {
            **row,
            "_source_row": str(index),
        }
        for index, row in enumerate(rows, start=2)
    ]
    indexed_rows.sort(key=lambda row: (_parse_time(row.get("time", "")), int(row["_source_row"])))

    for row in indexed_rows:
        alarm_type, classification_error = _classify_alarm_type(row, source_name=source_name)
        if classification_error:
            rejected.append(_rejected_item(source_name, row, classification_error))
            continue

        event, row_warnings = _build_event(
            alarm_type,
            row,
            assets=assets,
            devices=devices,
            rule_state=rule_state,
            source_name=source_name,
        )
        errors, validation_warnings = validate_event(event, schema)
        row_warnings.extend(validation_warnings)
        if errors:
            rejected.append(
                _rejected_item(
                    source_name,
                    row,
                    "; ".join(errors),
                    event=event,
                )
            )
            continue

        events.append(event)
        type_key = str(alarm_type)
        type_counts[type_key] = type_counts.get(type_key, 0) + 1
        for warning in row_warnings:
            warnings.append(
                {
                    "source": source_name,
                    "source_row": int(row["_source_row"]),
                    "alarm_type": alarm_type,
                    "message": warning,
                }
            )

    report = {
        "source": source_name,
        "input_rows": len(rows),
        "event_count": len(events),
        "rejected_count": len(rejected),
        "warning_count": len(warnings),
        "alarm_type_counts": type_counts,
        "warnings": warnings,
        "ok": len(rejected) == 0,
    }
    return {
        "events": events,
        "rejected": rejected,
        "report": report,
    }


def validate_event(event: dict[str, Any], schema: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors = []
    warnings = []
    alarm_type = event.get("alarm_type")
    alarm_schema = (schema.get("alarm_types") or {}).get(str(alarm_type))
    if not alarm_schema:
        return [f"不支持的 alarm_type: {alarm_type}"], warnings

    data = event.get("data")
    if not isinstance(data, dict):
        return ["data 必须是对象"], warnings

    required = alarm_schema.get("required") or []
    expected = set(required)
    missing = [field for field in required if not str(data.get(field, "")).strip()]
    if missing:
        errors.append("缺少必填字段: " + ", ".join(missing))

    extras = sorted(set(data) - expected)
    if extras:
        errors.append("包含协议外字段: " + ", ".join(extras))

    mac_field = "srp_mac" if alarm_type == 1 and "srp_mac" in data else "src_mac"
    mac_value = str(data.get(mac_field, "")).strip()
    if mac_value and not MAC_PATTERN.fullmatch(mac_value):
        warnings.append(f"{mac_field} 不是合法 MAC 地址")

    for field, value in data.items():
        if not field.endswith("_ip") or not str(value).strip():
            continue
        if not _is_ip_or_network(str(value)):
            warnings.append(f"{field} 不是标准 IP/CIDR，当前按防火墙地址对象保留")

    if alarm_type == 4:
        if data.get("policy") and data.get("policy") not in {"允许", "禁止", "代理"}:
            warnings.append("policy 不属于 允许、禁止或代理，当前按原始值保留")

    login_time = str(data.get("login_time", "")).strip()
    if login_time and _parse_time(login_time) == datetime.max:
        warnings.append("login_time 无法按支持的时间格式解析")

    return errors, warnings


def _classify_alarm_type(row: dict[str, str], *, source_name: str) -> tuple[int, str]:
    permissive = source_name.startswith("firewall_example")
    explicit = str(row.get("alarm_type", "")).strip()
    if explicit:
        try:
            alarm_type = int(explicit)
        except ValueError:
            return (4, "") if permissive else (0, f"alarm_type 不是整数: {explicit}")
        if alarm_type not in {1, 2, 3, 4}:
            return (4, "") if permissive else (0, f"不支持的 alarm_type: {alarm_type}")
        return alarm_type, ""

    event_type = str(row.get("event_type", "")).strip().lower()
    module = str(row.get("module", "")).strip().lower()
    action = str(row.get("event_action", "")).strip().lower()
    if permissive:
        if event_type == "admin_session" or module in {"terminal", "webui", "cli"}:
            if module == "webui":
                return 2, ""
            if module == "cli":
                return 3, ""
            if module == "terminal":
                return 1, ""
        return 4, ""

    if event_type == "policy_rule":
        if action not in ACTION_LABELS:
            return 0, f"策略动作不属于添加/修改/删除: {action or '空'}"
        return 4, ""
    if event_type == "admin_session":
        if action != "login":
            return 0, f"客户协议只接收登录事件，当前动作: {action or '空'}"
        if module == "webui":
            return 2, ""
        if module == "cli":
            return 3, ""
        if module == "terminal":
            return 1, ""
        return 0, f"无法确定登录事件 alarm_type，module={module or '空'}"
    return 0, f"客户协议未定义事件类型: {event_type or '空'}"


def _build_event(
    alarm_type: int,
    row: dict[str, str],
    *,
    assets: dict[str, dict[str, str]],
    devices: dict[str, dict[str, str]],
    rule_state: dict[tuple[str, str], dict[str, str]],
    source_name: str,
) -> tuple[dict[str, Any], list[str]]:
    warnings = []
    use_firewall_defaults = source_name.startswith("firewall_example")
    default_device = _firewall_default_device(devices) if use_firewall_defaults else {}
    device_name = _first(
        row.get("control_name"),
        row.get("device_name"),
        default_device.get("device_name") if use_firewall_defaults else "",
    )
    device = devices.get(device_name.casefold(), default_device if use_firewall_defaults else {})
    module = str(row.get("module", "")).strip().lower()
    source_ip = _first(
        row.get("src_ip"),
        row.get("management_ip"),
        _default_source_ip(module) if use_firewall_defaults else "",
    )
    asset = assets.get(source_ip, {})
    default_asset = _default_asset_for_module(assets, module) if use_firewall_defaults else {}
    login_account = _first(
        row.get("login_account"),
        row.get("user"),
        asset.get("default_user"),
        default_asset.get("default_user"),
        device.get("default_user"),
    )
    login_time = _first(row.get("login_time"), row.get("time"))

    if alarm_type in {1, 2, 3}:
        common = {
            "src_ip": source_ip,
            "dst_ip": _first(row.get("dst_ip"), device.get("management_ip")),
            "dst_port": _first(row.get("dst_port"), _default_login_port(alarm_type, device)),
            "login_account": login_account,
            "login_time": login_time,
        }
        mac = _first(
            row.get("src_mac"),
            row.get("srp_mac"),
            asset.get("src_mac"),
            default_asset.get("src_mac"),
        )
        if alarm_type == 1:
            data = {
                "src_ip": common["src_ip"],
                "src_mac": mac,
                "dst_ip": common["dst_ip"],
                "dst_port": common["dst_port"],
                "login_account": common["login_account"],
                "login_time": common["login_time"],
            }
        elif alarm_type == 2:
            data = {
                "src_ip": common["src_ip"],
                "src_mac": mac,
                "dst_ip": common["dst_ip"],
                "dst_port": common["dst_port"],
                "protocol": _protocol_label(_first(row.get("protocol"), device.get("protocol"), "TCP")),
                "login_account": common["login_account"],
                "login_time": common["login_time"],
            }
        else:
            data = {
                "src_ip": common["src_ip"],
                "src_mac": mac,
                "dst_ip": common["dst_ip"],
                "dst_port": common["dst_port"],
                "login_account": common["login_account"],
                "login_time": common["login_time"],
            }
        return {"alarm_type": alarm_type, "data": data}, warnings

    rule_key = (
        device_name.casefold(),
        _first(row.get("rule_id"), row.get("rule_key")),
    )
    previous = rule_state.get(rule_key, {})
    action = str(row.get("event_action", "")).strip().lower()
    policy_type = _first(row.get("policy_type"), previous.get("policy_type"))
    raw_policy = _first(row.get("policy"), row.get("pcpolicy"))
    policy_label = raw_policy if raw_policy in {"允许", "禁止", "代理"} else POLICY_LABELS.get(policy_type, "")
    src_ip = _first(
        row.get("src_addr"),
        row.get("src_ip"),
        previous.get("src_ip"),
        _default_source_ip(module) if use_firewall_defaults else "",
    )
    dst_ip = _first(
        row.get("dst_addr"),
        row.get("dst_ip"),
        previous.get("dst_ip"),
        device.get("management_ip") if use_firewall_defaults else "",
    )

    data = {
        "control_device_type": _first(
            row.get("control_device_type"),
            device.get("device_type"),
        ),
        "control_name": device_name,
        "control_ip": _first(row.get("control_ip"), device.get("management_ip")),
        "action": _action_label(action),
        "policy": _first(policy_label, "允许"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "login_account": login_account,
        "login_time": login_time,
    }

    if rule_key[1]:
        if action == "del":
            rule_state.pop(rule_key, None)
        else:
            rule_state[rule_key] = {
                "policy_type": policy_type,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            }
    else:
        warnings.append("策略日志没有 rule_id/rule_key，无法进行修改和删除状态关联")

    return {"alarm_type": 4, "data": data}, warnings


def _firewall_default_device(devices: dict[str, dict[str, str]]) -> dict[str, str]:
    return devices.get("themis", {})


def _default_source_ip(module: str) -> str:
    return "192.168.100.10" if module == "terminal" else "192.168.100.50"


def _default_asset_for_module(
    assets: dict[str, dict[str, str]],
    module: str,
) -> dict[str, str]:
    if module == "terminal":
        return assets.get("192.168.100.10", {})
    return assets.get("192.168.100.50", {})


def _default_login_port(alarm_type: int, device: dict[str, str]) -> str:
    if alarm_type == 2:
        return _first(device.get("web_port"), "443")
    return _first(device.get("cli_port"), device.get("terminal_port"), "22")


def _protocol_label(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "IP协议TCP"
    if text.startswith("IP协议"):
        return text
    return f"IP协议{text.upper()}"


def _action_label(action: str) -> str:
    text = str(action or "").strip()
    return _first(ACTION_LABELS.get(text.lower()), text, "修改")


def _load_csv_index(path: Path, key: str, *, casefold: bool = False) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    rows = _read_csv(path)
    indexed = {}
    for row in rows:
        value = str(row.get(key, "")).strip()
        if not value:
            continue
        indexed[value.casefold() if casefold else value] = row
    return indexed


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        return [
            {str(key): str(value or "").strip() for key, value in row.items()}
            for row in csv.DictReader(file)
        ]


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, list):
        return _schema_from_examples(payload)
    raise ValueError(f"客户事件 schema 必须是 JSON 对象或样例数组: {path}")


def _schema_from_examples(examples: list[Any]) -> dict[str, Any]:
    alarm_types: dict[str, dict[str, list[str]]] = {}
    for item in examples:
        if not isinstance(item, dict):
            continue
        alarm_type = item.get("alarm_type")
        data = item.get("data")
        if alarm_type in (None, "") or not isinstance(data, dict):
            continue
        key = str(alarm_type)
        fields = alarm_types.setdefault(key, {"required": []})["required"]
        for field in data:
            if field not in fields:
                fields.append(str(field))
    return {
        "schema_version": "1.0",
        "description": "Customer firewall alarm event output contract inferred from examples.",
        "alarm_types": alarm_types,
    }


def _write_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)
        file.write("\n")


def _first(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _parse_time(value: str) -> datetime:
    text = str(value or "").strip()
    for pattern in (
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue
    return datetime.max


def _is_ip_or_network(value: str) -> bool:
    text = value.strip()
    if text.lower() == "any":
        return True
    try:
        if "/" in text:
            ip_network(text, strict=False)
        else:
            ip_address(text)
        return True
    except ValueError:
        return False


def _rejected_item(
    source_name: str,
    row: dict[str, str],
    reason: str,
    *,
    event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item = {
        "source": source_name,
        "source_row": int(row.get("_source_row", "0") or 0),
        "reason": reason,
        "event_type": row.get("event_type", ""),
        "event_action": row.get("event_action", ""),
        "module": row.get("module", ""),
    }
    if event is not None:
        item["candidate_event"] = event
    return item


def _unique_paths(paths: Iterable[Path]) -> list[Path]:
    result = []
    seen = set()
    for path in paths:
        resolved = Path(path).resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        result.append(resolved)
    return result
