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
    "[authz_core:error] [pid <*>] [client <*>] AH01630: client denied by server configuration: <*>": 1,
    "[php7:error] [pid <*>] [client <*>] script <*> not found or unable to stat": 10,
    "[authz_core:error] [pid <*>] [client <*>] AH01630: client denied by server configuration: <*> referer: <*>": 2,
    "[php7:error] [pid <*>] [client <*>] script <*> not found or unable to stat referer: <*>": 11,
    "[negotiation:error] [pid <*>] [client <*>] AH00687: Negotiation: discovered file(s) matching request: <*> (None could be negotiated)": 5,
    "[negotiation:error] [pid <*>] [client <*>] AH00687: Negotiation: discovered file(s) matching request: <*> (None could be negotiated). referer: <*>": 6,
    "[php7:error] [pid <*>] [client <*>] PHP Fatal error: require(): Failed opening required <*> (include_path='.:/usr/share/php') in <*> on line <*>": 9,
    "[php7:warn] [pid <*>] [client <*>] PHP Warning: scandir(): (errno <*>): No such file or directory in <*> on line <*>": 14,
    "[php7:warn] [pid <*>] [client <*>] PHP Warning: <*>": 12,
    "[autoindex:error] [pid <*>] [client <*>] AH01276: Cannot serve directory <*>: No matching DirectoryIndex (index.htmlindex.cgiindex.plindex.phpindex.xhtmlindex.htm) found and server-generated directory index forbidden by Options directive": 4,
    "[autoindex:error] [pid <*>] [client <*>] AH01276: Cannot serve directory <*>: No matching DirectoryIndex (<*>) found and server-generated directory index forbidden by Options directive referer: <*>": 3,
    "[php7:error] [pid <*>] [client <*>] PHP Fatal error: Uncaught Error: Call to undefined function <*>() in <*>Stack trace:\\#<*> {main} thrown in <*> on line <*>": 7,
    "[php7:error] [pid <*>] [client <*>] PHP Fatal error: Uncaught Error: Call to undefined function get_header() in /var/www/intranet.price.fox.org/wp-content/themes/<*>/index.php:<*>Stack trace:\\#<*> {main} thrown in /var/www/intranet.price.fox.org/wp-content/themes/<*>/index.php on line <*> referer: https://intranet.price.fox.org": 8,
    "[php7:warn] [pid <*>] [client <*>] PHP Warning: Use of undefined constant <*> - assumed <*> (this will throw an Error in a future version of PHP) in <*> on line <*>": 13,
}

BASE_RE = re.compile(
    r"^\[(?P<module>[^:\]]+):(?P<severity>[^\]]+)\] "
    r"\[pid (?P<pid>\d+)\] "
    r"\[client (?P<client>[^\]]+)\] "
    r"(?P<message>.*)$"
)

AUTHZ_RE = re.compile(
    r"^AH01630: client denied by server configuration: (?P<path>.+)$"
)
SCRIPT_NOT_FOUND_RE = re.compile(
    r"^script (?P<script>.+?) not found or unable to stat$"
)
NEGOTIATION_RE = re.compile(
    r"^AH00687: Negotiation: discovered file\(s\) matching request: (?P<path>.+?) "
    r"\(None could be negotiated\)\.?$"
)
AUTOINDEX_RE = re.compile(
    r"^AH01276: Cannot serve directory (?P<directory>.+?): "
    r"No matching DirectoryIndex \((?P<index_list>.+?)\) found, "
    r"and server-generated directory index forbidden by Options directive$"
)
PHP_REQUIRE_RE = re.compile(
    r"^PHP Fatal error: require\(\): Failed opening required (?P<required>.+?) "
    r"\(include_path='(?P<include_path>.+?)'\) in (?P<source_file>.+?) on line (?P<line>\d+)$"
)
PHP_UNDEFINED_FUNCTION_RE = re.compile(
    r"^PHP Fatal error: Uncaught Error: Call to undefined function (?P<func>[^()]+)\(\) "
    r"in (?P<error_file>.+?):(?P<error_line>\d+)\\nStack trace:\\n"
    r"(?P<stack_trace>#\d+ \{main\})\\n thrown in (?P<thrown_file>.+?) on line (?P<thrown_line>\d+)$"
)
PHP_WARNING_UNDEFINED_CONSTANT_RE = re.compile(
    r"^PHP Warning: Use of undefined constant (?P<constant>.+?) - assumed (?P<assumed>.+?) "
    r"\(this will throw an Error in a future version of PHP\) "
    r"in (?P<error_file>.+?) on line (?P<error_line>\d+)$"
)
PHP_WARNING_SCANDIR_ERRNO_RE = re.compile(
    r"^PHP Warning: scandir\(\): \(errno (?P<errno>\d+)\): No such file or directory "
    r"in (?P<file_path>.+?) on line (?P<line>\d+)$"
)
PHP_WARNING_GENERIC_RE = re.compile(
    r"^PHP Warning: (?P<warning_message>.+?) in (?P<file_path>.+?) on line (?P<line>\d+)$"
)


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


def split_client_endpoint(client_text):
    text = (client_text or "").strip()
    if not text:
        return "", ""
    if text.count(":") >= 2 and not text.startswith("["):
        ip, sep, port = text.rpartition(":")
        return ip, port if sep else ""
    if ":" in text:
        ip, port = text.rsplit(":", 1)
        return ip, port
    return text, ""


def strip_quotes(text):
    value = (text or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def split_referer(message):
    if ", referer: " in message:
        body, referer = message.rsplit(", referer: ", 1)
        return body, referer.strip()
    return message, ""


def parse_error_content(content):
    match = BASE_RE.match((content or "").strip())
    if not match:
        return {
            "module": "",
            "severity": "",
            "pid": "",
            "client": "",
            "src_ip": "",
            "src_port": "",
            "referer": "",
            "message": "",
            "event_type_canonical": "",
            "event_action_canonical": "",
            "status_code": "",
            "outcome": "",
        }

    module = match.group("module")
    severity = match.group("severity")
    pid = match.group("pid")
    client = match.group("client")
    src_ip, src_port = split_client_endpoint(client)
    message, referer = split_referer(match.group("message"))

    parsed = {
        "module": module,
        "severity": severity,
        "pid": pid,
        "client": client,
        "src_ip": src_ip,
        "src_port": src_port,
        "referer": referer,
        "message": message,
        "event_type_canonical": "",
        "event_action_canonical": "",
        "status_code": "",
        "outcome": "failure",
        "program": module,
        "user": "",
        "user_agent": "",
        "http_version": "",
        "bytes_sent": "",
        "error_code": "",
        "object_name": "",
        "module_field": module,
        "component": module,
        "log_component": f"{module}:{severity}",
        "php7_error": f"{module}:{severity}" if module == "php7" else "",
        "negotiation_error": severity if module == "negotiation" else "",
        "autoindex_error": severity if module == "autoindex" else "",
        "log_level": severity,
        "error_type": "Fatal error" if severity == "error" and module == "php7" and message.startswith("PHP Fatal error:") else ("Warning" if severity == "warn" and module == "php7" else ""),
        "error_message": "",
        "undefined_function": "",
        "error_file": "",
        "error_line": "",
        "thrown_file": "",
        "thrown_line": "",
        "stack_trace": "",
        "include_path": "",
        "source_file": "",
        "line_number": "",
        "warning_message": "",
        "undefined_constant": "",
        "assumed_constant": "",
        "directory_index": "",
        "directory_index_list": "",
        "requested_resource": "",
        "denied_path": "",
        "requested_file": "",
        "script": "",
        "required_file": "",
        "file_path": "",
        "errno": "",
        "error_function": "",
    }

    ah_match = re.match(r"^(AH\d+):", message)
    if ah_match:
        parsed["error_code"] = ah_match.group(1)

    authz_match = AUTHZ_RE.match(message)
    if authz_match:
        denied = authz_match.group("path").strip()
        parsed["requested_resource"] = denied
        parsed["denied_path"] = denied
        parsed["object_name"] = denied
        parsed["event_type_canonical"] = "access_denied"
        parsed["event_action_canonical"] = "denied"
        parsed["status_code"] = "403"
        return parsed

    script_match = SCRIPT_NOT_FOUND_RE.match(message)
    if script_match:
        script = strip_quotes(script_match.group("script"))
        parsed["script"] = script
        parsed["object_name"] = script
        parsed["event_type_canonical"] = "script_not_found"
        parsed["event_action_canonical"] = "not_found"
        parsed["status_code"] = "404"
        return parsed

    negotiation_match = NEGOTIATION_RE.match(message)
    if negotiation_match:
        requested = negotiation_match.group("path").strip()
        parsed["requested_file"] = requested
        parsed["object_name"] = requested
        parsed["event_type_canonical"] = "negotiation_error"
        parsed["event_action_canonical"] = "failed"
        parsed["status_code"] = "406"
        return parsed

    autoindex_match = AUTOINDEX_RE.match(message)
    if autoindex_match:
        directory = autoindex_match.group("directory").strip()
        index_list = autoindex_match.group("index_list").strip()
        parsed["directory"] = directory
        parsed["object_name"] = directory
        parsed["directory_index"] = index_list
        parsed["directory_index_list"] = index_list
        parsed["event_type_canonical"] = "directory_index_forbidden"
        parsed["event_action_canonical"] = "denied"
        parsed["status_code"] = "403"
        return parsed

    require_match = PHP_REQUIRE_RE.match(message)
    if require_match:
        required_file = strip_quotes(require_match.group("required"))
        source_file = require_match.group("source_file").strip()
        line = require_match.group("line").strip()
        include_path = require_match.group("include_path").strip()
        parsed["required_file"] = required_file
        parsed["object_name"] = required_file
        parsed["include_path"] = include_path
        parsed["source_file"] = source_file
        parsed["line_number"] = line
        parsed["error_function"] = "require()"
        parsed["error_message"] = message
        parsed["event_type_canonical"] = "php_error"
        parsed["event_action_canonical"] = "failed"
        parsed["status_code"] = "500"
        return parsed

    undefined_function_match = PHP_UNDEFINED_FUNCTION_RE.match(message)
    if undefined_function_match:
        undefined_function = undefined_function_match.group("func").strip()
        error_file = undefined_function_match.group("error_file").strip()
        error_line = undefined_function_match.group("error_line").strip()
        stack_trace = undefined_function_match.group("stack_trace").strip()
        thrown_file = undefined_function_match.group("thrown_file").strip()
        thrown_line = undefined_function_match.group("thrown_line").strip()
        parsed["undefined_function"] = undefined_function
        parsed["error_message"] = message
        parsed["error_file"] = error_file
        parsed["error_line"] = error_line
        parsed["object_name"] = error_file
        parsed["stack_trace"] = stack_trace
        parsed["thrown_file"] = thrown_file
        parsed["thrown_line"] = thrown_line
        parsed["event_type_canonical"] = "php_error"
        parsed["event_action_canonical"] = "failed"
        parsed["status_code"] = "500"
        return parsed

    undefined_constant_match = PHP_WARNING_UNDEFINED_CONSTANT_RE.match(message)
    if undefined_constant_match:
        undefined_constant = undefined_constant_match.group("constant").strip()
        assumed_constant = undefined_constant_match.group("assumed").strip()
        error_file = undefined_constant_match.group("error_file").strip()
        error_line = undefined_constant_match.group("error_line").strip()
        parsed["undefined_constant"] = undefined_constant
        parsed["assumed_constant"] = assumed_constant
        parsed["error_file"] = error_file
        parsed["error_line"] = error_line
        parsed["object_name"] = error_file
        parsed["event_type_canonical"] = "php_error"
        parsed["event_action_canonical"] = "failed"
        return parsed

    scandir_errno_match = PHP_WARNING_SCANDIR_ERRNO_RE.match(message)
    if scandir_errno_match:
        errno = scandir_errno_match.group("errno").strip()
        file_path = scandir_errno_match.group("file_path").strip()
        line = scandir_errno_match.group("line").strip()
        parsed["errno"] = errno
        parsed["error_code"] = errno
        parsed["file_path"] = file_path
        parsed["object_name"] = file_path
        parsed["line_number"] = line
        parsed["event_type_canonical"] = "php_error"
        parsed["event_action_canonical"] = "failed"
        return parsed

    warning_match = PHP_WARNING_GENERIC_RE.match(message)
    if warning_match:
        warning_message = warning_match.group("warning_message").strip()
        file_path = warning_match.group("file_path").strip()
        line = warning_match.group("line").strip()
        parsed["warning_message"] = warning_message
        parsed["file_path"] = file_path
        parsed["object_name"] = file_path
        parsed["line_number"] = line
        if warning_message.startswith("require("):
            parsed["error_function"] = "require()"
        parsed["event_type_canonical"] = "php_error"
        parsed["event_action_canonical"] = "failed"
        return parsed

    return parsed


def build_source_values(parsed):
    return {
        "module": parsed["module"],
        "severity": parsed["severity"],
        "pid": parsed["pid"],
        "client": parsed["client"],
        "error_code": parsed["error_code"],
        "requested_resource": parsed["requested_resource"],
        "denied_path": parsed["denied_path"],
        "referer": parsed["referer"],
        "directory": parsed.get("directory", ""),
        "directory_index": parsed["directory_index"],
        "directory_index_list": parsed["directory_index_list"],
        "negotiation_error": parsed["negotiation_error"],
        "requested_file": parsed["requested_file"],
        "php7_error": parsed["php7_error"],
        "error_message": parsed["error_message"],
        "undefined_function": parsed["undefined_function"],
        "error_file": parsed["error_file"],
        "error_line": parsed["error_line"],
        "thrown_file": parsed["thrown_file"],
        "thrown_line": parsed["thrown_line"],
        "stack_trace": parsed["stack_trace"],
        "log_component": parsed["log_component"],
        "error_type": parsed["error_type"],
        "error_function": parsed["error_function"],
        "required_file": parsed["required_file"],
        "include_path": parsed["include_path"],
        "source_file": parsed["source_file"],
        "line_number": parsed["line_number"],
        "script": parsed["script"],
        "log_level": parsed["log_level"],
        "warning_message": parsed["warning_message"],
        "file_path": parsed["file_path"],
        "undefined_constant": parsed["undefined_constant"],
        "assumed_constant": parsed["assumed_constant"],
        "errno": parsed["errno"],
        "autoindex_error": parsed["autoindex_error"],
        "component": parsed["component"],
        "program": parsed["program"],
        "src_ip": parsed["src_ip"],
        "src_port": parsed["src_port"],
    }


def read_input_csv(input_csv, template_index):
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
            if template not in template_index:
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


def resolve_field_value(parsed, source_values, source_name, output_key):
    if source_name == "client":
        if output_key == "src_ip":
            return parsed["src_ip"]
        if output_key == "src_port":
            return parsed["src_port"]
        return parsed["client"]
    if source_name == "component" and output_key == "program":
        return parsed["program"]
    if source_name == "error_type" and output_key == "event_type":
        return parsed["error_type"]
    if source_name == "error_function" and output_key == "event_action":
        return parsed["error_function"]
    return source_values.get(source_name, "")


def extract_row(input_row, specs, columns, log_source, default_host, template_index):
    row = {c: "" for c in columns}
    row["log"] = input_row["log"]
    row["time"] = normalize_time(input_row["timestamp"])
    row["log_source"] = log_source
    row["host"] = default_host

    parsed = parse_error_content(input_row["log"])
    source_values = build_source_values(parsed)
    spec_index = template_index[input_row["regex_template"]]

    row["program"] = parsed["program"]
    row["pid"] = parsed["pid"]
    row["src_ip"] = parsed["src_ip"]
    row["src_port"] = parsed["src_port"]
    row["referer"] = parsed["referer"]
    row["severity"] = parsed["severity"]
    row["error_code"] = parsed["error_code"]
    row["object_name"] = parsed["object_name"]

    for field in specs[spec_index]:
        output_key = field["output"]
        if output_key not in row:
            continue
        value = resolve_field_value(parsed, source_values, field["source"], output_key)
        if value is None:
            value = ""
        row[output_key] = str(value)

    row["event_type"] = parsed["event_type_canonical"]
    if not row["event_action"]:
        row["event_action"] = parsed["event_action_canonical"]
    row["status_code"] = parsed["status_code"]
    row["outcome"] = parsed["outcome"]
    row["severity"] = parsed["severity"]

    if not row["program"]:
        row["program"] = parsed["program"]
    if not row["pid"]:
        row["pid"] = parsed["pid"]
    if not row["src_ip"]:
        row["src_ip"] = parsed["src_ip"]
    if not row["src_port"]:
        row["src_port"] = parsed["src_port"]
    if not row["object_name"]:
        row["object_name"] = parsed["object_name"]
    if not row["error_code"]:
        row["error_code"] = parsed["error_code"]

    return row


def save_output_rows(output_csv, rows, columns):
    with open(output_csv, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def run(args):
    template_index = load_template_index(args.input_csv)
    input_rows = read_input_csv(args.input_csv, template_index)
    specs, mapped_outputs, plain_fields = load_pairs_specs(args.pairs_json, expected_count=len(template_index))
    columns = build_columns(mapped_outputs, plain_fields)
    output_rows = [
        extract_row(
            input_row,
            specs,
            columns,
            args.log_source,
            args.default_host,
            template_index,
        )
        for input_row in input_rows
    ]
    os.makedirs(os.path.dirname(args.output_csv) or ".", exist_ok=True)
    save_output_rows(args.output_csv, output_rows, columns)


def main():
    parser = argparse.ArgumentParser(
        description="Extract intranet_server apache error 3.csv parameters and save CSV."
    )
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--pairs-json", required=True)
    parser.add_argument("--output-csv", required=True)
    parser.add_argument("--log-source", default="apache")
    parser.add_argument("--default-host", default="intranet.price.fox.org")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
