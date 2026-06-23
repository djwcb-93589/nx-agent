from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
from collections import OrderedDict


FIXED_COLUMNS = [
    "time",
    "device_name",
    "module",
    "event_type",
    "event_action",
    "user",
    "management_ip",
    "outcome",
    "src_addr",
    "dst_addr",
    "interface_in",
    "interface_out",
    "src_zone",
    "dst_zone",
    "service",
    "policy_id",
    "rule_id",
    "rule_key",
    "policy_type",
    "rule_state",
    "log_enabled",
    "translated_src",
    "public_ip",
    "internal_addr",
    "public_service",
    "internal_service",
    "zone_name",
    "blacklist_ip",
]

PREFIX_RE = re.compile(r"^(?P<host>\S+)\s+(?P<program>[^:\s]+):\s+(?P<body>.*)$")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

MODULE_ALIASES = {
    "策略": "policy",
    "黑名单": "blacklist",
}

ACTION_ALIASES = {
    "添加": "add",
    "修改": "set",
    "编辑": "set",
    "设置": "set",
    "删除": "del",
    "清除": "clear",
    "批量加载": "bulk_load",
    "登录": "login",
    "退出": "logout",
    "离开": "leave",
    "显示": "show",
    "恢复": "startup",
}

POLICY_ID_TYPES = {
    "50": "deny",
    "55": "permit",
    "56": "nat",
    "57": "port_map",
    "58": "ip_map",
    "59": "proxy",
    "61": "masquerade",
    "62": "permit_nat",
    "101": "active_defense",
    "102": "uids",
    "103": "antiddos",
    "104": "psa",
}


def parse_field_item(field_item):
    if not isinstance(field_item, list) or not field_item:
        return ""
    raw_name = str(field_item[0]).strip()
    if not raw_name:
        return ""
    if "->" in raw_name:
        return raw_name.split("->", 1)[1].strip()
    return raw_name


def load_pair_columns(pairs_json):
    if not pairs_json:
        return []
    try:
        with open(pairs_json, "r", encoding="utf-8") as file:
            raw = json.load(file)
    except FileNotFoundError:
        return []

    columns = []
    seen = set()
    if not isinstance(raw, list):
        return columns
    for entry in raw:
        if not isinstance(entry, list):
            continue
        for field_item in entry:
            output = parse_field_item(field_item)
            if output and output not in seen:
                columns.append(output)
                seen.add(output)
    return columns


def build_columns(pair_columns):
    columns = []
    seen = set()
    allowed = set(FIXED_COLUMNS)
    for column in [*FIXED_COLUMNS, *pair_columns]:
        if column not in allowed:
            continue
        if column and column not in seen:
            columns.append(column)
            seen.add(column)
    return columns


def read_input_rows(input_csv):
    with open(input_csv, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        fieldnames = {name.lower(): name for name in (reader.fieldnames or [])}
        timestamp_col = fieldnames.get("timestamp")
        content_col = fieldnames.get("content")
        eventid_col = fieldnames.get("eventid")
        template_col = fieldnames.get("regextemplate")
        if not content_col:
            raise SystemExit("Input CSV must contain a Content column.")
        rows = []
        for row in reader:
            rows.append(
                {
                    "timestamp": row.get(timestamp_col, "") if timestamp_col else "",
                    "log": row.get(content_col, ""),
                    "event_id": row.get(eventid_col, "") if eventid_col else "",
                    "regex_template": row.get(template_col, "") if template_col else "",
                }
            )
        return rows


def split_prefix(log_text):
    text = (log_text or "").strip()
    match = PREFIX_RE.match(text)
    if match and "devid=" in match.group("body"):
        return match.group("host"), match.group("program"), match.group("body")
    return "", "", text


def parse_kv_pairs(text):
    lexer = shlex.shlex(text, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|\S*)', text)

    pairs = OrderedDict()
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        key = key.strip()
        if not key:
            continue
        pairs[key] = value.strip().strip('"')
    return pairs


def normalize_module(value):
    text = (value or "").strip()
    return MODULE_ALIASES.get(text, text).lower()


def normalize_action(value):
    text = (value or "").strip()
    return ACTION_ALIASES.get(text, text).lower()


def normalize_switch(value):
    text = (value or "").strip().lower()
    if text in {"on", "enable", "enabled", "开启"}:
        return "enabled"
    if text in {"off", "disable", "disabled", "关闭"}:
        return "disabled"
    return value or ""


def normalize_outcome(value, message):
    raw = (value or "").strip()
    msg = (message or "").strip()
    raw_lower = raw.lower()
    if raw in {"0", "成功"} or raw_lower in {"success", "ok", "true"}:
        return "success"
    if raw in {"1", "失败"} or raw_lower in {"failure", "failed", "fail", "error", "false"}:
        return "failure"
    if "错误" in msg or "失败" in msg or "error" in msg.lower():
        return "failure"
    return "unknown" if not raw else raw


def infer_policy_type(policy_id, display_message):
    policy_type = POLICY_ID_TYPES.get((policy_id or "").strip())
    if policy_type:
        return policy_type

    msg = (display_message or "").lower()
    if "antiddos" in msg:
        return "antiddos"
    if "psa" in msg:
        return "psa"
    if "uids" in msg:
        return "uids"
    if "端口映射" in msg or "portmap" in msg:
        return "port_map"
    if "ip 映射" in msg or "ipmap" in msg:
        return "ip_map"
    if "nat" in msg:
        return "nat"
    if "代理" in msg or "proxy" in msg:
        return "proxy"
    if "伪装" in msg or "masquerade" in msg:
        return "masquerade"
    if "主动防御" in msg or "active" in msg:
        return "active_defense"
    if "deny" in msg:
        return "deny"
    if "允许" in msg or "permit" in msg:
        return "permit"
    return ""


def infer_event_type(module, prefix_program, action, display_message):
    combined = " ".join([module or "", prefix_program or "", action or "", display_message or ""]).lower()
    if module in {"webui", "cli"}:
        return "admin_session"
    if module == "policy" or prefix_program == "rule":
        return "policy_rule"
    if module == "zone" or prefix_program == "zone":
        return "zone_config"
    if module == "blacklist" or "黑名单" in combined or "blacklist" in combined:
        return "blacklist"
    if module == "fc" or prefix_program == "fc":
        return "flow_control"
    return module or prefix_program or "firewall_event"


def extract_zone_name(display_message):
    text = display_message or ""
    patterns = [
        r"(?:安全域名字|安全域名称)\s+(\S+)",
        r"seczone\s+name\s+(\S+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip(",，")
    return ""


def extract_interface_set(display_message):
    text = display_message or ""
    match = re.search(r"(?:接口集合|ifset)\s+(.+)$", text, flags=re.IGNORECASE)
    if not match:
        return ""
    value = match.group(1).strip()
    if value.lower() in {"", "ifset"}:
        return ""
    return value


def extract_blacklist_ip(event_type, display_message):
    if event_type != "blacklist":
        return ""
    match = IP_RE.search(display_message or "")
    return match.group(0) if match else ""


def compose_rule_key(device_name, policy_id, rule_id):
    parts = [device_name or "firewall"]
    if policy_id:
        parts.append(f"policy:{policy_id}")
    if rule_id:
        parts.append(f"rule:{rule_id}")
    return "|".join(parts) if len(parts) > 1 else ""


def normalize_row(input_row, columns, log_source):
    prefix_host, prefix_program, body = split_prefix(input_row["log"])
    kv = parse_kv_pairs(body)
    display_message = kv.get("dsp_msg") or kv.get("msg") or ""
    module = normalize_module(kv.get("mod") or prefix_program)
    action = normalize_action(kv.get("act"))
    device_name = kv.get("dname") or prefix_host
    policy_id = kv.get("policy", "")
    rule_id = kv.get("id", "")
    event_type = infer_event_type(module, prefix_program.lower(), action, display_message)

    row = {column: "" for column in columns}
    row.update(
        {
            "log": input_row["log"],
            "time": kv.get("date") or input_row.get("timestamp", ""),
            "log_source": log_source,
            "host": device_name,
            "program": prefix_program or module,
            "device_id": kv.get("devid", ""),
            "device_name": device_name,
            "module": module,
            "event_type": event_type,
            "event_action": action,
            "user": kv.get("user") or kv.get("admin") or "",
            "actor_user": kv.get("user") or kv.get("admin") or "",
            "management_ip": kv.get("from", ""),
            "src_ip": kv.get("from", ""),
            "src_addr": kv.get("sa", ""),
            "dst_addr": kv.get("da", ""),
            "src_port": kv.get("sport", ""),
            "dst_port": kv.get("dport", ""),
            "interface_in": kv.get("iif", ""),
            "interface_out": kv.get("oif", ""),
            "src_zone": kv.get("izone", ""),
            "dst_zone": kv.get("ozone", ""),
            "interface_set": extract_interface_set(display_message),
            "zone_name": extract_zone_name(display_message),
            "service": kv.get("service", ""),
            "policy_id": policy_id,
            "rule_id": rule_id,
            "rule_key": compose_rule_key(device_name, policy_id, rule_id),
            "policy_type": infer_policy_type(policy_id, display_message),
            "rule_state": normalize_switch(kv.get("active", "")),
            "log_enabled": normalize_switch(kv.get("log", "")),
            "translated_src": kv.get("sat", ""),
            "public_ip": kv.get("pa", ""),
            "internal_addr": kv.get("ia", ""),
            "public_service": kv.get("ps", ""),
            "internal_service": kv.get("is", ""),
            "command": kv.get("cmd", ""),
            "result": kv.get("result", ""),
            "outcome": normalize_outcome(kv.get("result", ""), display_message),
            "display_message": display_message,
            "client_agent": kv.get("agent", ""),
            "blacklist_ip": "",
            "fwlog": kv.get("fwlog", ""),
            "priority": kv.get("pri", ""),
            "version": kv.get("ver", ""),
        }
    )
    row["blacklist_ip"] = extract_blacklist_ip(row["event_type"], display_message)

    key_aliases = {
        "devid": "device_id",
        "dname": "device_name",
        "mod": "module",
        "act": "event_action",
        "from": "management_ip",
        "policy": "policy_id",
        "id": "rule_id",
        "iif": "interface_in",
        "oif": "interface_out",
        "izone": "src_zone",
        "ozone": "dst_zone",
        "sat": "translated_src",
        "pa": "public_ip",
        "ia": "internal_addr",
        "ps": "public_service",
        "is": "internal_service",
        "dsp_msg": "display_message",
        "msg": "display_message",
        "agent": "client_agent",
        "pri": "priority",
        "ver": "version",
    }
    for key, value in kv.items():
        target = key_aliases.get(key, key)
        if target in row and not row[target]:
            row[target] = value
    return row


def save_output_rows(output_csv, rows, columns):
    with open(output_csv, "w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def run(args):
    input_rows = read_input_rows(args.input_csv)
    columns = build_columns(load_pair_columns(args.pairs_json))
    output_rows = [normalize_row(row, columns, args.log_source) for row in input_rows]
    save_output_rows(args.output_csv, output_rows, columns)
    print(f"extracted firewall params rows={len(output_rows)} columns={len(columns)}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Extract structured parameters from device firewall logs.")
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--pairs-json", required=True)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--log-source", default="firewall")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
