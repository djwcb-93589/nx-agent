import argparse
import csv
import json
import os
import re
from datetime import datetime, timezone


FIXED_COLUMNS = [
    "log",
    "time",
    "log_source",
    "host",
    "program",
    "pid",
    "event_type",
    "qname",
    "qtype",
    "src_ip",
    "dst_ip",
    "answer_kind",
    "status_code",
    "response_source",
    "outcome",
]

TEMPLATE_TO_SPEC_INDEX = {
    "dnsmasq[<*>]: reply <*> is <*>": 10,
    "dnsmasq[14522]: forwarded <*> to <*>": 1,
    "dnsmasq[<*>]: forwarded <*> to <*>": 8,
    "dnsmasq[14522]: query[AAAA] <*> from <*>": 3,
    "dnsmasq[14522]: query[A] <*> from <*>": 4,
    "dnsmasq[1774]: query[A] <*> from 10.35.35.<*>": 5,
    "dnsmasq[<*>]: query[<*>] <*> from <*>": 9,
    "dnsmasq[<*>]: cached <*> is <*>": 6,
    "dnsmasq[14522]: nameserver 127.0.0.<*> refused to do a recursive query": 2,
    "dnsmasq[<*>]: failed to access /etc/dnsmasq.d/dnsmasq-resolv.conf: No such file or directory": 7,
}


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

    if "->" in raw_name:
        source_name, output_name = raw_name.split("->", 1)
        source_name = source_name.strip()
        output_name = output_name.strip()
    else:
        source_name = raw_name
        output_name = raw_name

    return {"source": source_name, "output": output_name}


def load_columns(pairs_json_path):
    with open(pairs_json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    mapped_outputs = []
    mapped_seen = set()
    plain_fields = []
    plain_seen = set()

    for entry in raw:
        for field_item in entry:
            parsed = parse_field_item(field_item)
            if not parsed:
                continue
            raw_name = str(field_item[0])
            if "->" in raw_name:
                if parsed["output"] and parsed["output"] not in mapped_seen:
                    mapped_outputs.append(parsed["output"])
                    mapped_seen.add(parsed["output"])
            else:
                if parsed["output"] and parsed["output"] not in plain_seen:
                    plain_fields.append(parsed["output"])
                    plain_seen.add(parsed["output"])

    columns = []
    seen = set()
    for col in FIXED_COLUMNS:
        if col not in seen:
            columns.append(col)
            seen.add(col)
    for col in mapped_outputs:
        if col and col not in seen:
            columns.append(col)
            seen.add(col)
    for col in plain_fields:
        if col and col not in seen:
            columns.append(col)
            seen.add(col)
    return columns


def failure_status(value):
    text = (value or "").strip()
    upper = text.upper()
    if upper in {"NXDOMAIN", "REFUSED", "SERVFAIL", "FORMERR", "NOTIMP"}:
        return upper
    if upper.startswith("NODATA"):
        return text
    return ""


def parse_row(row, columns, regex_cache, log_source):
    out = {c: "" for c in columns}
    out["log"] = row["Content"]
    out["time"] = normalize_time(row["Timestamp"])
    out["log_source"] = log_source

    template = row["RegexTemplate"]
    pattern = row["RegexPattern"]
    if pattern not in regex_cache:
        regex_cache[pattern] = re.compile(pattern)
    match = regex_cache[pattern].match(row["Content"])
    groups = list(match.groups()) if match else []

    out["program"] = "dnsmasq"

    if template == "dnsmasq[<*>]: reply <*> is <*>":
        if len(groups) >= 3:
            out["pid"] = groups[0]
            out["qname"] = groups[1]
            out["answer_kind"] = groups[2]
        out["event_type"] = "reply"
        status = failure_status(out["answer_kind"])
        if status:
            out["status_code"] = status
            out["outcome"] = "failure"
        elif out["answer_kind"]:
            out["outcome"] = "success"

    elif template == "dnsmasq[14522]: forwarded <*> to <*>":
        if len(groups) >= 2:
            out["pid"] = "14522"
            out["qname"] = groups[0]
            out["dst_ip"] = groups[1]
        out["event_type"] = "forwarded"
        out["response_source"] = "upstream"

    elif template == "dnsmasq[<*>]: forwarded <*> to <*>":
        if len(groups) >= 3:
            out["pid"] = groups[0]
            out["qname"] = groups[1]
            out["dst_ip"] = groups[2]
            out["process_id"] = groups[0]
        out["event_type"] = "forwarded"
        out["response_source"] = "upstream"

    elif template == "dnsmasq[14522]: query[AAAA] <*> from <*>":
        if len(groups) >= 2:
            out["pid"] = "14522"
            out["qtype"] = "AAAA"
            out["qname"] = groups[0]
            out["src_ip"] = groups[1]
        out["event_type"] = "query"

    elif template == "dnsmasq[14522]: query[A] <*> from <*>":
        if len(groups) >= 2:
            out["pid"] = "14522"
            out["qtype"] = "A"
            out["qname"] = groups[0]
            out["src_ip"] = groups[1]
            out["dnsmasq_pid"] = "14522"
        out["event_type"] = "query"

    elif template == "dnsmasq[1774]: query[A] <*> from 10.35.35.<*>":
        if len(groups) >= 2:
            src_ip = f"10.35.35.{groups[1]}"
            out["pid"] = "1774"
            out["qtype"] = "A"
            out["qname"] = groups[0]
            out["src_ip"] = src_ip
            out["dnsmasq_pid"] = "1774"
        out["event_type"] = "query"

    elif template == "dnsmasq[<*>]: query[<*>] <*> from <*>":
        if len(groups) >= 4:
            out["pid"] = groups[0]
            out["qtype"] = groups[1]
            out["qname"] = groups[2]
            out["src_ip"] = groups[3]
            out["process_id"] = groups[0]
        out["event_type"] = "query"

    elif template == "dnsmasq[<*>]: cached <*> is <*>":
        if len(groups) >= 3:
            out["pid"] = groups[0]
            out["qname"] = groups[1]
            out["qtype"] = groups[2]
            out["process_id"] = groups[0]
        out["event_type"] = "cached"
        out["response_source"] = "cache"
        status = failure_status(out["qtype"])
        if status:
            out["status_code"] = status
            out["outcome"] = "failure"
        elif out["qtype"]:
            out["outcome"] = "success"

    elif template == "dnsmasq[14522]: nameserver 127.0.0.<*> refused to do a recursive query":
        if len(groups) >= 1:
            out["pid"] = "14522"
            out["dst_ip"] = f"127.0.0.{groups[0]}"
            out["dnsmasq_pid"] = "14522"
        out["event_type"] = "nameserver_error"
        out["status_code"] = "REFUSED"
        out["response_source"] = "upstream"
        out["outcome"] = "failure"

    elif template == "dnsmasq[<*>]: failed to access /etc/dnsmasq.d/dnsmasq-resolv.conf: No such file or directory":
        if len(groups) >= 1:
            out["pid"] = groups[0]
            out["process_id"] = groups[0]
            out["file_path"] = "/etc/dnsmasq.d/dnsmasq-resolv.conf"
            out["error_message"] = "No such file or directory"
        out["event_type"] = "file_access_error"
        out["status_code"] = "FILE_ACCESS_ERROR"
        out["outcome"] = "failure"

    return out


def main():
    parser = argparse.ArgumentParser(
        description="Fast materialization for inet-firewall dnsmasq 3.csv extraction."
    )
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--pairs-json", required=True)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--log-source", default="dns")
    args = parser.parse_args()

    columns = load_columns(args.pairs_json)
    regex_cache = {}
    rows_written = 0

    os.makedirs(os.path.dirname(args.output_csv) or ".", exist_ok=True)

    with open(args.input_csv, "r", encoding="utf-8-sig", newline="") as src_f, open(
        args.output_csv, "w", encoding="utf-8-sig", newline=""
    ) as out_f:
        reader = csv.DictReader(src_f)
        writer = csv.DictWriter(out_f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()

        for row in reader:
            writer.writerow(parse_row(row, columns, regex_cache, args.log_source))
            rows_written += 1
            if rows_written % 50000 == 0:
                print(f"progress_rows={rows_written}", flush=True)


if __name__ == "__main__":
    main()
