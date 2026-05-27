import argparse
import csv
import json
import os
import re
from collections import OrderedDict
from datetime import datetime, timezone


FIXED_COLUMNS = [
    "log",
    "time",
    "log_source",
    "host",
    "program",
    "pid",
    "event_type",
    "event_action",
    "user",
    "src_ip",
    "src_port",
    "object_name",
    "status_code",
    "outcome",
    "referer",
    "user_agent",
    "http_version",
    "bytes_sent",
    "severity",
    "error_code",
]

TEMPLATE_TO_SPEC_INDEX = {
    '<*> - - "-" <*> <*> "-" "-"': 4,
    '<*> - - "<*> <*> HTTP/<*>" <*> <*> <*> "<*>"': 8,
    '10.35.35.<*> - - "<*> HTTP/1.<*>" <*> <*> "-" "WordPress/5.8.<*>; https://intranet.price.fox.org"': 1,
    '<*> - - "<*> <*> HTTP/1.<*>" <*> <*> <*> "<*>"': 5,
    '172.17.130.<*> - - "<*> HTTP/1.<*>" <*> <*> "-" "Mozilla/5.<*> (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"': 2,
    '::<*> - - "OPTIONS * HTTP/1.<*>" <*> <*> "-" "Apache/2.4.<*> (Ubuntu) OpenSSL/1.1.<*> (internal dummy connection)"': 3,
    '<*> - - "GET <*> HTTP/1.<*>" <*> <*> "-" "Mozilla/4.<*> (compatible; MSIE 6.<*>; Windows NT 5.1)"': 9,
    '<*> - - "<*> <*> HTTP/1.<*>" <*> <*> <*> "Mozilla/5.<*> (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.<*>"': 7,
    '<*> - - "<*> <*> HTTP/1.<*>" <*> <*> <*> "Mozilla/5.<*> (X11; Linux x86_64) AppleWebKit/537.<*> (KHTML like Gecko) HeadlessChrome/95.0.4638.<*> Safari/537.<*>"': 6,
}

CONTENT_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+(?P<ident>\S+)\s+(?P<authuser>\S+)\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\S+)\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"$'
)

REQUEST_RE = re.compile(r"^(?P<method>\S+)\s+(?P<target>\S+)\s+(?P<protocol>\S+)$")


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


def load_pairs_specs(pairs_json_path):
    with open(pairs_json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if not isinstance(raw, list):
        raise SystemExit("Pairs JSON must be a list.")
    if len(raw) != len(TEMPLATE_TO_SPEC_INDEX):
        raise SystemExit(
            f"Pairs JSON count ({len(raw)}) does not match template mapping count ({len(TEMPLATE_TO_SPEC_INDEX)})."
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


def split_target(target):
    text = (target or "").strip()
    if not text or text == "-":
        return "", "", ""
    if "?" in text:
        path, query = text.split("?", 1)
        return text, path, query
    return text, text, ""


def normalize_http_version(version_text):
    text = (version_text or "").strip()
    if not text:
        return ""
    if text.startswith("HTTP/"):
        return text
    return f"HTTP/{text}"


def parse_access_content(content):
    match = CONTENT_RE.match((content or "").strip())
    if not match:
        return {
            "src_ip": "",
            "user": "",
            "request": "",
            "status_code": "",
            "bytes_sent": "",
            "referer": "",
            "user_agent": "",
            "event_action": "",
            "request_uri": "",
            "request_path": "",
            "query_string": "",
            "http_version": "",
        }

    src_ip = match.group("src_ip")
    authuser = match.group("authuser")
    request = match.group("request")
    status_code = match.group("status")
    bytes_sent = match.group("size")
    referer = match.group("referer")
    user_agent = match.group("user_agent")

    user = "" if authuser == "-" else authuser
    if referer == "-":
        referer = ""
    if user_agent == "-":
        user_agent = ""
    event_action = ""
    request_uri = ""
    request_path = ""
    query_string = ""
    http_version = ""

    if request != "-":
        request_match = REQUEST_RE.match(request)
        if request_match:
            event_action = request_match.group("method")
            request_uri, request_path, query_string = split_target(request_match.group("target"))
            http_version = normalize_http_version(request_match.group("protocol"))

    return {
        "src_ip": src_ip,
        "user": user,
        "request": request,
        "status_code": status_code,
        "bytes_sent": bytes_sent,
        "referer": referer,
        "user_agent": user_agent,
        "event_action": event_action,
        "request_uri": request_uri,
        "request_path": request_path,
        "query_string": query_string,
        "http_version": http_version,
    }


def build_source_values(parsed):
    return {
        "src_ip": parsed["src_ip"],
        "client_ip": parsed["src_ip"],
        "http_method": parsed["event_action"],
        "request_method": parsed["event_action"],
        "request_uri": parsed["request_uri"],
        "request_path": parsed["request_path"],
        "http_path": parsed["request_path"],
        "query_string": parsed["query_string"],
        "request_query": parsed["query_string"],
        "http_query": parsed["query_string"],
        "http_version": parsed["http_version"],
        "status_code": parsed["status_code"],
        "response_size": parsed["bytes_sent"],
        "bytes_sent": parsed["bytes_sent"],
        "referer": parsed["referer"],
        "user_agent": parsed["user_agent"],
        "user": parsed["user"],
    }


def derive_event_type(parsed):
    if parsed["request"] == "-" and parsed["status_code"] == "408":
        return "request_timeout"
    return "http_request"


def derive_outcome(status_code):
    try:
        code = int(str(status_code).strip())
    except ValueError:
        return ""
    if 200 <= code < 400:
        return "success"
    if 400 <= code < 600:
        return "failure"
    return "unknown"


def read_input_csv(input_csv):
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
            if template not in TEMPLATE_TO_SPEC_INDEX:
                raise SystemExit(f"Unexpected RegexTemplate: {template}")
            rows.append(
                {
                    "timestamp": row.get(ts_col, ""),
                    "log": row.get(content_col, ""),
                    "event_id": row.get(eventid_col, "").strip(),
                    "regex_template": template,
                }
            )
    return rows


def extract_row(input_row, specs, columns, log_source, default_host, default_program):
    row = {c: "" for c in columns}
    row["log"] = input_row["log"]
    row["time"] = normalize_time(input_row["timestamp"])
    row["log_source"] = log_source
    row["host"] = default_host
    row["program"] = default_program

    parsed = parse_access_content(input_row["log"])
    source_values = build_source_values(parsed)
    spec_index = TEMPLATE_TO_SPEC_INDEX[input_row["regex_template"]]

    for field in specs[spec_index]:
        output_key = field["output"]
        if output_key not in row:
            continue
        value = source_values.get(field["source"], "")
        if value is None:
            value = ""
        if isinstance(value, str):
            row[output_key] = value
        else:
            row[output_key] = str(value)

    if not row["event_action"]:
        row["event_action"] = parsed["event_action"]
    if not row["src_ip"]:
        row["src_ip"] = parsed["src_ip"]
    if not row["object_name"]:
        row["object_name"] = parsed["request_path"] or parsed["request_uri"]
    if not row["status_code"]:
        row["status_code"] = parsed["status_code"]
    if not row["referer"]:
        row["referer"] = parsed["referer"]
    if not row["user_agent"]:
        row["user_agent"] = parsed["user_agent"]
    if not row["http_version"]:
        row["http_version"] = parsed["http_version"]
    if not row["bytes_sent"]:
        row["bytes_sent"] = parsed["bytes_sent"]
    if not row["user"]:
        row["user"] = parsed["user"]

    row["event_type"] = derive_event_type(parsed)
    row["outcome"] = derive_outcome(row["status_code"])
    return row


def save_output_rows(output_csv, rows, columns):
    with open(output_csv, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def run(args):
    input_rows = read_input_csv(args.input_csv)
    specs, mapped_outputs, plain_fields = load_pairs_specs(args.pairs_json)
    columns = build_columns(mapped_outputs, plain_fields)
    output_rows = [
        extract_row(
            input_row,
            specs,
            columns,
            args.log_source,
            args.default_host,
            args.default_program,
        )
        for input_row in input_rows
    ]
    os.makedirs(os.path.dirname(args.output_csv) or ".", exist_ok=True)
    save_output_rows(args.output_csv, output_rows, columns)


def main():
    parser = argparse.ArgumentParser(
        description="Extract intranet_server apache access 3.csv parameters and save CSV."
    )
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--pairs-json", required=True)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--log-source", default="apache")
    parser.add_argument("--default-host", default="intranet.price.fox.org")
    parser.add_argument("--default-program", default="apache")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
