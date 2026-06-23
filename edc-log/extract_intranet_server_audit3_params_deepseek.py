import argparse
import csv
import json
import os
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone

import requests

from env_utils import get_env, load_dotenv
from run import _normalize_audit_line, _normalize_prefixed_template

load_dotenv()

DEFAULT_BASE_URL = get_env("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEFAULT_MODEL = get_env("DEEPSEEK_PARAM_MODEL", "deepseek-chat")
DEFAULT_API_KEY = ""

FIXED_COLUMNS = [
    "log",
    "time",
    "log_source",
    "host",
    "event_type",
    "event_id",
    "user",
    "auid",
    "uid",
    "session_id",
    "tty",
    "terminal",
    "src_ip",
    "src_hostname",
    "pid",
    "ppid",
    "process_exe",
    "process_name",
    "process_title",
    "command",
    "cwd",
    "syscall",
    "outcome",
]

CORE_COLUMNS = {"log", "time", "log_source", "event_id"}

TEMPLATE_TO_SPEC_INDEX = {
    "type=PROCTITLE msg=audit: proctitle=<*>": 8,
    "type=USER_CMD msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='cwd=\"<*>\" cmd=<*> terminal=<*> res=success'": 14,
    "type=LOGIN msg=audit: pid=<*> uid=<*> old-auid=<*> auid=<*> tty=(none) old-ses=<*> ses=<*> res=<*>": 7,
    "type=SERVICE_STOP msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='unit=<*> comm=\"systemd\" exe=\"/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'": 10,
    "type=USER_START msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:session_open acct=\"<*>\" exe=\"<*>\" hostname=? addr=? terminal=<*> res=success'": 18,
    "type=USER_END msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:session_close acct=\"<*>\" exe=\"<*>\" hostname=<*> addr=<*> terminal=<*> res=<*>'": 15,
    "type=USER_START msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:session_open acct=\"<*>\" exe=\"<*>\" hostname=<*> addr=<*> terminal=<*> res=<*>'": 17,
    "type=USER_AUTH msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:authentication acct=<*> exe=<*> hostname=? addr=? terminal=<*> res=<*>'": 13,
    "type=CRED_REFR msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:setcred acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=<*> res=success'": 6,
    "type=USER_LOGIN msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=login id=<*> exe=\"/usr/sbin/sshd\" hostname=<*> addr=<*> terminal=/dev/pts/0 res=success'": 16,
    "type=CRED_DISP msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:setcred acct=\"root\" exe=<*> hostname=? addr=? terminal=<*> res=success'": 5,
    "type=CRED_DISP msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:setcred acct=\"<*>\" exe=\"/usr/sbin/sshd\" hostname=<*> addr=<*> terminal=ssh res=success'": 4,
    "type=USER_ACCT msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:accounting acct=\"<*>\" exe=\"<*>\" hostname=<*> addr=<*> terminal=<*> res=<*>'": 12,
    "type=SERVICE_START msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='unit=<*> comm=\"systemd\" exe=\"/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'": 9,
    "type=CRED_ACQ msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:setcred acct=\"<*>\" exe=\"/usr/sbin/sshd\" hostname=<*> addr=<*> terminal=ssh res=success'": 2,
    "type=AVC msg=audit: apparmor=\"STATUS\" operation=\"profile_replace\" info=\"same as current profile skipping\" profile=\"unconfined\" name=<*> pid=<*> comm=\"apparmor_parser\"": 1,
    "type=CRED_ACQ msg=audit: pid=<*> uid=<*> auid=<*> ses=<*> msg='op=PAM:setcred acct=\"<*>\" exe=\"<*>\" hostname=? addr=? terminal=<*> res=success'": 3,
    "type=SYSCALL msg=audit: arch=c000003e syscall=<*> success=yes exit=<*> a0=<*> a1=<*> a2=<*> a3=<*> items=<*> ppid=<*> pid=<*> auid=<*> uid=<*> gid=<*> euid=<*> suid=<*> fsuid=<*> egid=<*> sgid=<*> fsgid=<*> tty=pts0 ses=<*> comm=\"apparmor_parser\" exe=\"/sbin/apparmor_parser\" key=(null)": 11,
}


def resolve_api_key(cli_value):
    if cli_value and cli_value.strip():
        return cli_value.strip()
    for key in ("DEEPSEEK_API_KEY", "DS_TOKEN", "OPENAI_API_KEY", "OPENAI_KEY"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return DEFAULT_API_KEY


def normalize_time(timestamp_text):
    text = (timestamp_text or "").strip()
    if not text:
        return ""
    if text.startswith("audit(") and ":" in text and ")" in text:
        inner = text[len("audit(") : text.rfind(")")]
        epoch_text = inner.split(":", 1)[0]
        try:
            epoch_val = float(epoch_text)
            return datetime.fromtimestamp(epoch_val, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return text
    return text


def parse_field_item(field_item):
    if not isinstance(field_item, list) or not field_item:
        return None

    raw_name = str(field_item[0]).strip()
    if not raw_name:
        return None

    definition = ""
    if len(field_item) >= 2 and field_item[1] is not None:
        definition = str(field_item[1]).strip()

    example = ""
    if len(field_item) >= 3 and field_item[2] is not None:
        example = str(field_item[2]).strip()

    if "->" in raw_name:
        source_name, output_name = raw_name.split("->", 1)
        source_name = source_name.strip()
        output_name = output_name.strip()
    else:
        source_name = raw_name
        output_name = raw_name

    return {
        "source": source_name,
        "output": output_name,
        "definition": definition,
        "example": example,
    }


def extract_template_text(template_entry):
    text = str(template_entry or "").strip()
    if text.startswith("Template:"):
        text = text[len("Template:") :].strip()
    if "\nSamples:" in text:
        text = text.split("\nSamples:", 1)[0].strip()
    return text


def load_template_index(input_csv):
    template_json_path = os.path.join(os.path.dirname(input_csv), "template2samples.json")
    if os.path.isfile(template_json_path):
        with open(template_json_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        entries = raw[0] if isinstance(raw, list) and raw and isinstance(raw[0], list) else raw
        template_index = {}
        for index, entry in enumerate(entries, start=1):
            template = extract_template_text(entry)
            if template:
                template_index[template] = index
        if template_index:
            return template_index

    return dict(TEMPLATE_TO_SPEC_INDEX)


def template_mode(input_csv):
    normalized_path = str(input_csv).lower().replace("\\", "/")
    if "audit" in normalized_path:
        return "audit"
    if "/auth/" in normalized_path:
        return "auth"
    return "generic"


def load_template_key_lookup(input_csv):
    mode = template_mode(input_csv)
    with open(input_csv, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = {name.lower(): name for name in (reader.fieldnames or [])}
        content_col = fieldnames.get("content")
        template_col = fieldnames.get("regextemplate")
        if not content_col or not template_col:
            return {}

        first_content_by_template = OrderedDict()
        for row in reader:
            template = row.get(template_col, "")
            if template and template not in first_content_by_template:
                first_content_by_template[template] = row.get(content_col, "")

    lookup = {}
    for template, sample in first_content_by_template.items():
        if mode == "audit":
            lookup[template] = _normalize_audit_line(template)
        elif mode == "auth":
            lookup[template] = _normalize_prefixed_template(template, sample)
        else:
            lookup[template] = template
    return lookup


def read_input_csv(input_csv, template_index, template_lookup):
    with open(input_csv, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = {name.lower(): name for name in (reader.fieldnames or [])}
        ts_col = fieldnames.get("timestamp")
        content_col = fieldnames.get("content")
        eventid_col = fieldnames.get("eventid")
        template_col = fieldnames.get("regextemplate")
        if not ts_col or not content_col or not eventid_col or not template_col:
            raise SystemExit(
                "Input CSV must contain Timestamp, Content, EventId, and RegexTemplate columns."
            )

        rows = []
        for row in reader:
            template = row.get(template_col, "")
            template_key = template_lookup.get(template, template)
            if template_key not in template_index:
                raise SystemExit(f"Unexpected RegexTemplate: {template}")
            rows.append(
                {
                    "timestamp": row.get(ts_col, ""),
                    "log": row.get(content_col, ""),
                    "event_id": row.get(eventid_col, "").strip(),
                    "regex_template": template_key,
                    "raw_regex_template": template,
                }
            )
    return rows


def load_pairs_specs(pairs_json_path, expected_count=None):
    with open(pairs_json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if not isinstance(raw, list):
        raise SystemExit("Pairs JSON must be a list.")
    if expected_count is not None and len(raw) != expected_count:
        raise SystemExit(
            f"Pairs JSON count ({len(raw)}) does not match template mapping count ({expected_count})."
        )

    specs = {}
    mapped_outputs = []
    mapped_seen = set()
    plain_fields = []
    plain_seen = set()

    for index, entry in enumerate(raw, start=1):
        bucket = OrderedDict()
        for field_item in entry:
            parsed = parse_field_item(field_item)
            if not parsed:
                continue

            if "->" in str(field_item[0]):
                if parsed["output"] and parsed["output"] not in mapped_seen:
                    mapped_outputs.append(parsed["output"])
                    mapped_seen.add(parsed["output"])
            else:
                if parsed["output"] and parsed["output"] not in plain_seen:
                    plain_fields.append(parsed["output"])
                    plain_seen.add(parsed["output"])

            key = f"{parsed['source']}->{parsed['output']}"
            if key not in bucket:
                bucket[key] = parsed
            else:
                if not bucket[key]["definition"] and parsed["definition"]:
                    bucket[key]["definition"] = parsed["definition"]
                if not bucket[key]["example"] and parsed["example"]:
                    bucket[key]["example"] = parsed["example"]

        specs[index] = list(bucket.values())

    return specs, mapped_outputs, plain_fields


def build_columns(mapped_outputs, plain_fields):
    cols = []
    seen = set()
    for col in FIXED_COLUMNS:
        if col not in seen:
            cols.append(col)
            seen.add(col)
    for col in mapped_outputs:
        if col and col not in seen:
            cols.append(col)
            seen.add(col)
    for col in plain_fields:
        if col and col not in seen:
            cols.append(col)
            seen.add(col)
    return cols


def compact_fields(fields_for_template):
    out = []
    for field in fields_for_template:
        definition = (field.get("definition") or "").strip()
        if len(definition) > 180:
            definition = definition[:180]
        out.append(
            {
                "source": field.get("source", ""),
                "output": field.get("output", ""),
                "definition": definition,
                "example": field.get("example", ""),
            }
        )
    return out


def chunked(items, size):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def build_messages(template_text, event_spec, items, output_keys):
    system_prompt = (
        "You extract structured fields from Linux audit logs.\n"
        "Each event spec item defines source field -> output field plus definition and example.\n"
        "The example is the strongest extraction hint.\n"
        "Extract only fields requested by the event spec.\n"
        "Follow source/output mapping exactly: if the spec says op->event_type, write event_type, not op.\n"
        "If the spec has no arrow, write the original field name.\n"
        "Every row must include row_index plus every key listed in output_keys.\n"
        "If a requested key cannot be found, set it to empty string.\n"
        "Never emit keys outside output_keys.\n"
        "Use only the provided log content. Do not invent values.\n"
        "Do not change or infer time, log_source, event_id, or log.\n"
        "Return ONLY JSON with shape {\"columns\":[\"row_index\", ...output_keys], \"rows\":[[row_index, ...values]]}.\n"
        "Each row array must follow the exact column order and include every output key."
    )
    payload = {
        "regex_template": template_text,
        "event_spec": event_spec,
        "items": items,
        "output_keys": output_keys,
    }
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]


def call_chat(base_url, api_key, model, messages, timeout_sec, max_tokens):
    url = base_url.rstrip("/") + "/v1/chat/completions"
    body = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "max_tokens": max_tokens,
    }
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    resp = requests.post(url, headers=headers, json=body, timeout=(10, timeout_sec))
    if resp.status_code >= 400:
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:400]}")

    obj = resp.json()
    try:
        content = obj["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        rows = parsed.get("rows")
        if not isinstance(rows, list):
            raise ValueError("rows is not a list")

        columns = parsed.get("columns")
        if isinstance(columns, list) and columns:
            normalized = []
            for row in rows:
                if not isinstance(row, list):
                    continue
                item = {}
                for idx, col in enumerate(columns):
                    if idx < len(row):
                        item[str(col)] = row[idx]
                    else:
                        item[str(col)] = ""
                normalized.append(item)
            return normalized

        return rows
    except Exception as exc:
        raise RuntimeError(f"Bad LLM response: {obj}") from exc


def run_batch(args, api_key, template_text, fields, items, output_keys):
    messages = build_messages(template_text, compact_fields(fields), items, output_keys)
    last_err = None
    for attempt in range(max(1, args.max_retries)):
        try:
            return call_chat(
                args.base_url,
                api_key,
                args.model,
                messages,
                timeout_sec=args.timeout_sec,
                max_tokens=args.max_tokens,
            )
        except Exception as exc:
            last_err = exc
            time.sleep(min(2 * (attempt + 1), 6))
    raise RuntimeError(f"Batch failed after retries: {last_err}") from last_err


def normalize_output_row(input_row, llm_row, columns, log_source, allowed_keys):
    row = {c: "" for c in columns}
    row["log"] = input_row["log"]
    row["time"] = normalize_time(input_row["timestamp"])
    row["log_source"] = log_source
    row["event_id"] = input_row["event_id"]
    if isinstance(llm_row, dict):
        for col in columns:
            if col in CORE_COLUMNS or col not in allowed_keys:
                continue
            value = llm_row.get(col, "")
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool)) and str(value).strip():
                row[col] = str(value)
    return row


def load_existing_output(output_csv, columns, expected_len):
    if not os.path.exists(output_csv):
        return None
    with open(output_csv, "r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if len(rows) != expected_len:
        raise SystemExit(
            f"Existing output row count ({len(rows)}) does not match input row count ({expected_len})."
        )
    existing_columns = list(rows[0].keys()) if rows else columns
    if existing_columns != columns:
        raise SystemExit("Existing output header does not match current header.")
    return rows


def save_output_rows(output_csv, final_rows, columns):
    with open(output_csv, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in final_rows:
            writer.writerow(row)


def parse_selected_templates(raw_value):
    if not raw_value or not raw_value.strip():
        return None
    return {part.strip() for part in raw_value.split("||") if part.strip()}


def parse_selected_spec_indexes(raw_value):
    if not raw_value or not raw_value.strip():
        return None
    values = set()
    for part in raw_value.split(","):
        text = part.strip()
        if not text:
            continue
        try:
            values.add(int(text))
        except ValueError as exc:
            raise SystemExit(f"Invalid spec index: {text}") from exc
    return values


def run(args):
    template_index = load_template_index(args.input_csv)
    template_lookup = load_template_key_lookup(args.input_csv)
    input_rows = read_input_csv(args.input_csv, template_index, template_lookup)
    pair_specs, mapped_outputs, plain_fields = load_pairs_specs(
        args.pairs_json, expected_count=len(template_index)
    )
    columns = build_columns(mapped_outputs, plain_fields)

    template_to_fields = {}
    template_allowed_keys = {}
    for template_text, spec_index in template_index.items():
        fields = pair_specs[spec_index]
        template_to_fields[template_text] = fields

        allowed = []
        seen = set()
        for field in fields:
            key = field["output"]
            if key in CORE_COLUMNS or not key or key in seen:
                continue
            allowed.append(key)
            seen.add(key)
        template_allowed_keys[template_text] = allowed

    selected_templates = parse_selected_templates(args.only_template)
    selected_spec_indexes = parse_selected_spec_indexes(args.only_spec_index)
    if selected_templates and selected_spec_indexes:
        raise SystemExit("Use either --only-template or --only-spec-index, not both.")
    grouped = OrderedDict()
    for idx, row in enumerate(input_rows):
        grouped.setdefault(row["regex_template"], []).append((idx, row))

    if selected_templates:
        unknown_templates = selected_templates.difference(grouped.keys())
        if unknown_templates:
            raise SystemExit(f"Unknown template(s): {list(unknown_templates)}")
    if selected_spec_indexes:
        unknown_specs = selected_spec_indexes.difference(set(template_index.values()))
        if unknown_specs:
            raise SystemExit(f"Unknown spec index(es): {sorted(unknown_specs)}")

    api_key = resolve_api_key(args.api_key)
    if not api_key:
        raise SystemExit("Missing DeepSeek API key.")

    os.makedirs(os.path.dirname(args.output_csv) or ".", exist_ok=True)

    existing_rows = load_existing_output(args.output_csv, columns, len(input_rows))
    if existing_rows is None:
        final_rows = [
            normalize_output_row(input_row, {}, columns, args.log_source, set())
            for input_row in input_rows
        ]
    else:
        final_rows = existing_rows

    llm_results = {}
    processed = 0
    total = sum(
        len(indexed_rows)
        for template_text, indexed_rows in grouped.items()
        if (
            (not selected_templates or template_text in selected_templates)
            and (
                not selected_spec_indexes
                or template_index[template_text] in selected_spec_indexes
            )
        )
    )

    print(
        "template mapping:",
        json.dumps(
            {template: template_index[template] for template in grouped},
            ensure_ascii=False,
        ),
        flush=True,
    )

    for template_text, indexed_rows in grouped.items():
        if selected_templates and template_text not in selected_templates:
            continue
        if (
            selected_spec_indexes
            and template_index[template_text] not in selected_spec_indexes
        ):
            continue

        fields = template_to_fields[template_text]
        allowed_keys = template_allowed_keys[template_text]
        pending_rows = []
        allowed_key_set = set(allowed_keys)
        for idx, row in indexed_rows:
            existing = final_rows[idx]
            if any(str(existing.get(key, "")).strip() for key in allowed_key_set):
                continue
            pending_rows.append((idx, row))

        if not pending_rows:
            print(f"skip template already filled: {template_text}", flush=True)
            continue

        for batch in chunked(pending_rows, args.batch_size):
            items = [{"row_index": idx, "log": row["log"]} for idx, row in batch]
            try:
                returned_rows = run_batch(
                    args, api_key, template_text, fields, items, allowed_keys
                )
            except Exception as batch_exc:
                if args.fail_fast:
                    raise RuntimeError(
                        f"Batch failed for template={template_text}: {batch_exc}"
                    ) from batch_exc
                returned_rows = []
                for idx, row in batch:
                    single_item = [{"row_index": idx, "log": row["log"]}]
                    try:
                        single_rows = run_batch(
                            args, api_key, template_text, fields, single_item, allowed_keys
                        )
                        returned_rows.extend(single_rows)
                    except Exception:
                        returned_rows.append({"row_index": idx})

            returned_map = {}
            valid_indexes = {idx for idx, _ in batch}
            for returned in returned_rows:
                if not isinstance(returned, dict):
                    continue
                row_index = returned.get("row_index")
                try:
                    row_index = int(row_index)
                except (TypeError, ValueError):
                    continue
                if row_index in valid_indexes:
                    returned_map[row_index] = returned

            for idx, _ in batch:
                llm_results[idx] = returned_map.get(idx, {})
                final_rows[idx] = normalize_output_row(
                    input_rows[idx],
                    llm_results[idx],
                    columns,
                    args.log_source,
                    allowed_key_set,
                )
                processed += 1

            save_output_rows(args.output_csv, final_rows, columns)
            if processed % 100 == 0 or processed == total:
                print(f"progress {processed}/{total}", flush=True)

    save_output_rows(args.output_csv, final_rows, columns)


def main():
    parser = argparse.ArgumentParser(
        description="Extract intranet_server audit 3.csv parameters with DeepSeek and save CSV."
    )
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--pairs-json", required=True)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--log-source", default="audit")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-key", default="")
    parser.add_argument("--timeout-sec", type=int, default=45)
    parser.add_argument("--max-retries", type=int, default=2)
    parser.add_argument("--max-tokens", type=int, default=5000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--only-template", default="")
    parser.add_argument("--only-spec-index", default="")
    parser.add_argument("--fail-fast", action="store_true")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
