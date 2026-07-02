import argparse
import csv
import json
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone

import requests

from env_utils import get_env, load_dotenv

load_dotenv()

DEFAULT_BASE_URL = get_env(
    "GLM_BASE_URL",
    "https://api.z.ai/api/paas/v4/",
    aliases=("ZAI_BASE_URL", "OPENAI_BASE_URL", "LLM_BASE_URL"),
)
DEFAULT_MODEL = get_env(
    "GLM_PARAM_MODEL",
    "glm-5.2",
    aliases=("GLM_MODEL", "ZAI_MODEL", "LLM_MODEL"),
)
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

def resolve_api_key(cli_value):
    if cli_value and cli_value.strip():
        return cli_value.strip()
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


def extract_audit_type(log_text):
    match = re.search(r"\btype=([A-Za-z0-9_]+)\b", log_text or "")
    return match.group(1) if match else ""


def read_input_csv(input_csv):
    with open(input_csv, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = {name.lower(): name for name in (reader.fieldnames or [])}
        ts_col = fieldnames.get("timestamp")
        content_col = fieldnames.get("content")
        eventid_col = fieldnames.get("eventid")
        if not ts_col or not content_col or not eventid_col:
            raise SystemExit("Input CSV must contain Timestamp, Content, and EventId columns.")

        rows = []
        for row in reader:
            log_text = row.get(content_col, "")
            rows.append(
                {
                    "timestamp": row.get(ts_col, ""),
                    "log": log_text,
                    "event_id": row.get(eventid_col, "").strip(),
                    "audit_type": extract_audit_type(log_text),
                }
            )
    return rows


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


def load_pairs_by_type(pairs_json_path):
    with open(pairs_json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if not isinstance(raw, list):
        raise SystemExit("Pairs JSON must be a list.")

    type_to_fields = {}
    mapped_outputs = []
    mapped_seen = set()
    plain_fields = []
    plain_seen = set()

    for entry in raw:
        if not isinstance(entry, list):
            continue

        bucket = OrderedDict()
        audit_type = ""
        for field_item in entry:
            parsed = parse_field_item(field_item)
            if not parsed:
                continue

            if parsed["source"] == "type" and parsed["example"]:
                audit_type = parsed["example"]

            if "->" in str(field_item[0]):
                if parsed["output"] and parsed["output"] not in mapped_seen:
                    mapped_outputs.append(parsed["output"])
                    mapped_seen.add(parsed["output"])
            else:
                if parsed["output"] not in plain_seen:
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

        if not audit_type:
            raise SystemExit(f"Could not determine audit type for entry: {entry}")
        if audit_type in type_to_fields:
            raise SystemExit(f"Duplicate audit type in pairs JSON: {audit_type}")
        type_to_fields[audit_type] = list(bucket.values())

    return type_to_fields, mapped_outputs, plain_fields


def map_event_ids_to_fields(input_rows, type_to_fields):
    event_to_fields = {}
    mapping_summary = OrderedDict()
    seen_event_ids = OrderedDict()
    for row in input_rows:
        event_id = row["event_id"]
        if event_id not in seen_event_ids:
            seen_event_ids[event_id] = row["audit_type"]

    for event_id, audit_type in seen_event_ids.items():
        if not audit_type:
            raise SystemExit(f"Could not infer audit type from log for EventId={event_id}")
        if audit_type not in type_to_fields:
            known = ", ".join(sorted(type_to_fields))
            raise SystemExit(
                f"No pairs JSON entry matches audit type '{audit_type}' for EventId={event_id}. Known types: {known}"
            )
        event_to_fields[event_id] = type_to_fields[audit_type]
        mapping_summary[event_id] = audit_type

    return event_to_fields, mapping_summary


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


def compact_fields(fields_for_event):
    out = []
    for field in fields_for_event:
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


def build_messages(audit_type, event_spec, items, output_keys):
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
        "Return ONLY JSON with shape {\"rows\":[...]}.\n"
        "Each returned row must include row_index and only allowed output keys."
    )
    payload = {
        "audit_type": audit_type,
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
        rows = parsed["rows"]
        if not isinstance(rows, list):
            raise ValueError("rows is not a list")
        return rows
    except Exception as exc:
        raise RuntimeError(f"Bad LLM response: {obj}") from exc


def run_batch(args, api_key, audit_type, fields, items, output_keys):
    messages = build_messages(audit_type, compact_fields(fields), items, output_keys)
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


def parse_selected_event_ids(raw_value):
    if not raw_value or not raw_value.strip():
        return None
    return {part.strip() for part in raw_value.split(",") if part.strip()}


def run(args):
    input_rows = read_input_csv(args.input_csv)
    type_to_fields, mapped_outputs, plain_fields = load_pairs_by_type(args.pairs_json)
    event_to_fields, mapping_summary = map_event_ids_to_fields(input_rows, type_to_fields)
    columns = build_columns(mapped_outputs, plain_fields)
    event_allowed_keys = {}
    for event_id, fields in event_to_fields.items():
        allowed = []
        seen = set()
        for field in fields:
            key = field["output"]
            if key in CORE_COLUMNS or not key or key in seen:
                continue
            allowed.append(key)
            seen.add(key)
        event_allowed_keys[event_id] = allowed

    api_key = resolve_api_key(args.api_key)
    if not api_key:
        raise SystemExit("Missing GLM API key.")

    os.makedirs(os.path.dirname(args.output_csv) or ".", exist_ok=True)
    selected_event_ids = parse_selected_event_ids(args.only_event_id)

    grouped = OrderedDict()
    for idx, row in enumerate(input_rows):
        grouped.setdefault(row["event_id"], []).append((idx, row))

    print("event mapping:", json.dumps(mapping_summary, ensure_ascii=False), flush=True)

    if selected_event_ids:
        unknown_event_ids = selected_event_ids.difference(grouped.keys())
        if unknown_event_ids:
            raise SystemExit(f"Unknown EventId(s): {', '.join(sorted(unknown_event_ids))}")

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
        for event_id, indexed_rows in grouped.items()
        if not selected_event_ids or event_id in selected_event_ids
    )

    for event_id, indexed_rows in grouped.items():
        if selected_event_ids and event_id not in selected_event_ids:
            continue
        audit_type = mapping_summary[event_id]
        fields = event_to_fields[event_id]
        allowed_keys = event_allowed_keys[event_id]
        for batch in chunked(indexed_rows, args.batch_size):
            items = [{"row_index": idx, "log": row["log"]} for idx, row in batch]
            try:
                returned_rows = run_batch(args, api_key, audit_type, fields, items, allowed_keys)
            except Exception as batch_exc:
                if args.fail_fast:
                    raise RuntimeError(
                        f"Batch failed for EventId={event_id}, audit_type={audit_type}: {batch_exc}"
                    ) from batch_exc
                returned_rows = []
                for idx, row in batch:
                    single_item = [{"row_index": idx, "log": row["log"]}]
                    try:
                        single_rows = run_batch(
                            args, api_key, audit_type, fields, single_item, allowed_keys
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
                processed += 1

            if processed % 100 == 0 or processed == total:
                print(f"progress {processed}/{total}", flush=True)

    for idx, input_row in enumerate(input_rows):
        if selected_event_ids and input_row["event_id"] not in selected_event_ids:
            continue
        final_rows[idx] = normalize_output_row(
            input_row,
            llm_results.get(idx, {}),
            columns,
            args.log_source,
            set(event_allowed_keys[input_row["event_id"]]),
        )

    with open(args.output_csv, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in final_rows:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="Extract audit_internal_share 3.csv parameters with GLM and save CSV."
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
    parser.add_argument("--max-tokens", type=int, default=2500)
    parser.add_argument("--batch-size", type=int, default=40)
    parser.add_argument("--only-event-id", default="")
    parser.add_argument("--fail-fast", action="store_true")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
