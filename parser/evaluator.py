import argparse
import csv
import os
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import accuracy
import grouping
import llama_parser
import pandas as pd
import re
import regex_manager
from tqdm import tqdm

from env_utils import get_env, load_dotenv


REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT)
MONTH_PATTERN = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
WEEKDAY_PATTERN = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"

LEADING_TIMESTAMP_PATTERNS = [
    re.compile(
        rf"^(?P<timestamp>\[{WEEKDAY_PATTERN}\s+{MONTH_PATTERN}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?\s+\d{{4}}\])\s*"
    ),
    re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z| ?[+-]\d{2}:?\d{2})?)\s*"
    ),
    re.compile(
        rf"^(?P<timestamp>{MONTH_PATTERN}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}})\s+"
    ),
]

INLINE_TIMESTAMP_PATTERNS = [
    {
        "pattern": re.compile(
            rf"\s*(?P<timestamp>\[\d{{1,2}}/{MONTH_PATTERN}/\d{{4}}:\d{{2}}:\d{{2}}:\d{{2}}\s+[+-]\d{{4}}\])\s*"
        ),
        "replacement": " ",
    },
    {
        "pattern": re.compile(
            r"(?P<prefix>\bmsg=)audit\((?P<timestamp>\d+(?:\.\d+)?:\d+)\)(?P<suffix>:)"
        ),
        "replacement": r"\g<prefix>audit\g<suffix>",
        "extract_wrapper": ("audit(", ")"),
    },
]

benchmark_settings = {
    "HDFS": {
        "log_file": "HDFS/HDFS_2k.log",
        "log_format": "<Date> <Time> <Pid> <Level> <Component>: <Content>",
        "regex": [r"blk_-?\d+", r"(\d+\.){3}\d+(:\d+)?"],
    },
    "Hadoop": {
        "log_file": "Hadoop/Hadoop_2k.log",
        "log_format": r"<Date> <Time> <Level> \[<Process>\] <Component>: <Content>",
        "regex": [r"(\d+\.){3}\d+"],
    },
    "Spark": {
        "log_file": "Spark/Spark_2k.log",
        "log_format": "<Date> <Time> <Level> <Component>: <Content>",
        "regex": [r"(\d+\.){3}\d+", r"\b[KGTM]?B\b", r"([\w-]+\.){2,}[\w-]+"],
        "regex": [],
    },
    "Zookeeper": {
        "log_file": "Zookeeper/Zookeeper_2k.log",
        "log_format": r"<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>",
        "regex": [r"(/|)(\d+\.){3}\d+(:\d+)?"],
    },
    "BGL": {
        "log_file": "BGL/BGL_2k.log",
        "log_format": "<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>",
        "regex": [r"core\.\d+"],
    },
    "HPC": {
        "log_file": "HPC/HPC_2k.log",
        "log_format": "<LogId> <Node> <Component> <State> <Time> <Flag> <Content>",
        "regex": [r"=\d+"],
    },
    "Thunderbird": {
        "log_file": "Thunderbird/Thunderbird_2k.log",
        "log_format": r"<Label> <Timestamp> <Date> <User> <Month> <Day> <Time> <Location> <Component>(\[<PID>\])?: <Content>",
        "regex": [r"(\d+\.){3}\d+"],
    },
    "Windows": {
        "log_file": "Windows/Windows_2k.log",
        "log_format": "<Date> <Time>, <Level>                  <Component>    <Content>",
        "regex": [r"0x.*?\s"],
    },
    "Linux": {
        "log_file": "Linux/Linux_2k.log",
        "log_format": r"<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>",
        "regex": [r"(\d+\.){3}\d+", r"\d{2}:\d{2}:\d{2}"],
    },
    "Android": {
        "log_file": "Android/Android_2k.log",
        "log_format": "<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>",
        "regex": [
            r"(/[\w-]+)+",
            r"([\w-]+\.){2,}[\w-]+",
            r"\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b",
        ],
    },
    "HealthApp": {
        "log_file": "HealthApp/HealthApp_2k.log",
        "log_format": r"<Time>\|<Component>\|<Pid>\|<Content>",
        "regex": [],
    },
    "Apache": {
        "log_file": "Apache/Apache_2k.log",
        "log_format": r"\[<Time>\] \[<Level>\] <Content>",
        "regex": [r"(\d+\.){3}\d+"],
    },
    "Proxifier": {
        "log_file": "Proxifier/Proxifier_2k.log",
        "log_format": r"\[<Time>\] <Program> - <Content>",
        "regex": [
            r"<\d+\ssec",
            r"([\w-]+\.)+[\w-]+(:\d+)?",
            r"\d{2}:\d{2}(:\d{2})*",
            r"[KGTM]B",
        ],
    },
    "OpenSSH": {
        "log_file": "OpenSSH/OpenSSH_2k.log",
        "log_format": r"<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>",
        "regex": [r"(\d+\.){3}\d+", r"([\w-]+\.){2,}[\w-]+"],
    },
    "OpenStack": {
        "log_file": "OpenStack/OpenStack_2k.log",
        "log_format": r"<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>",
        "regex": [r"((\d+\.){3}\d+,?)+", r"/.+?\s", r"\d+"],
    },
    "Mac": {
        "log_file": "Mac/Mac_2k.log",
        "log_format": r"<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>",
        "regex": [r"([\w-]+\.){2,}[\w-]+"],
    },
}


def log_file_to_logs(
    log_file, logformat, first_lines_percent=100, start_line_percent=0
):
    """Function to transform log file to dataframe, reads from a specific start line and reads up to a given percent of lines."""
    headers, regex = generate_logformat_regex(logformat)
    log_messages = []
    with open(log_file, "r") as fin:
        lines = fin.readlines()
        total_lines = len(lines)  
        start_line = int(
            total_lines * start_line_percent / 100
        )  
        lines_to_read = int(
            (total_lines - start_line) * (first_lines_percent / 100)
        )  
        for i, line in enumerate(
            lines[start_line : start_line + lines_to_read], start=start_line
        ):

            try:
                match = regex.search(line.strip())
                if match:
                    message = [match.group(header) for header in headers]
                    log_messages.append(message)
            except Exception as e:
                print("Skip line: ", line)

    logdf = pd.DataFrame(log_messages, columns=headers)
    logdf.insert(
        0, "LineId", range(start_line + 1, start_line + len(log_messages) + 1)
    )  

    array_result = logdf.loc[:, ["Content"]].values
    list_result = [list(row) for row in array_result]
    return list_result


def read_column_from_csv(file_path, column_name="Content"):
    column_data = []
    with open(file_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if column_name in row:
                column_data.append(row[column_name])
            else:
                raise ValueError(
                    f"The column '{column_name}' does not exist in the CSV file."
                )
    return column_data


def read_logs_from_plaintext(file_path):
    logs = []
    with open(file_path, mode="r", encoding="utf-8", errors="replace") as file:
        for line in file:
            content = line.rstrip("\r\n")
            if content.strip():
                logs.append(content)
    return logs


def normalize_preprocessed_content(content):
    return re.sub(r"\s{2,}", " ", content).strip()


def extract_timestamp_and_content(log_line):
    content = log_line.strip()

    for pattern in LEADING_TIMESTAMP_PATTERNS:
        match = pattern.match(content)
        if match:
            timestamp = match.group("timestamp")
            stripped_content = normalize_preprocessed_content(content[match.end() :])
            if not stripped_content:
                stripped_content = content
            return timestamp, stripped_content

    for inline_pattern in INLINE_TIMESTAMP_PATTERNS:
        match = inline_pattern["pattern"].search(content)
        if match:
            timestamp = match.group("timestamp")
            wrapper = inline_pattern.get("extract_wrapper")
            if wrapper:
                timestamp = f"{wrapper[0]}{timestamp}{wrapper[1]}"
            stripped_content = inline_pattern["pattern"].sub(
                inline_pattern["replacement"], content, count=1
            )
            stripped_content = normalize_preprocessed_content(stripped_content)
            if not stripped_content:
                stripped_content = content
            return timestamp, stripped_content

    return "", content


def preprocess_logs(raw_logs):
    processed_logs = []
    preprocessed_rows = []

    for line_id, original_content in enumerate(raw_logs, start=1):
        timestamp, content = extract_timestamp_and_content(original_content)
        processed_logs.append(content)
        preprocessed_rows.append(
            {
                "LineId": line_id,
                "Timestamp": timestamp,
                "Content": content,
                "OriginalContent": original_content,
            }
        )

    return processed_logs, preprocessed_rows


def save_preprocessed_logs(preprocessed_rows, file_path):
    pd.DataFrame(preprocessed_rows).to_csv(file_path, index=False, encoding="utf-8")
    return file_path


def regex_pattern_to_template(regex_pattern):
    if regex_pattern is None:
        return ""

    text = str(regex_pattern).strip()
    if not text:
        return text

    if text.startswith("^"):
        text = text[1:]
    if text.endswith("$"):
        text = text[:-1]

    chars = []
    i = 0
    length = len(text)

    while i < length:
        char = text[i]

        if char == "\\":
            if i + 1 < length:
                next_char = text[i + 1]
                if next_char == " ":
                    chars.append(" ")
                else:
                    chars.append(next_char)
                i += 2
                continue
            chars.append(char)
            i += 1
            continue

        if char == "(":
            depth = 1
            i += 1
            escaped = False
            while i < length and depth > 0:
                current = text[i]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == "(":
                    depth += 1
                elif current == ")":
                    depth -= 1
                i += 1
            chars.append("<*>")
            continue

        chars.append(char)
        i += 1

    cleaned = "".join(chars)
    cleaned = re.sub(r"<\*>\?", "<*>", cleaned)
    cleaned = re.sub(r"\.\*\??", "<*>", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
    return cleaned


def build_result_rows_with_timestamps(parsed_results, preprocessed_rows):
    row_queues = defaultdict(deque)
    for row in preprocessed_rows:
        row_queues[row["Content"]].append(row)

    enriched_rows = []
    for content, event_id, regex_template in parsed_results:
        if row_queues[content]:
            source_row = row_queues[content].popleft()
        else:
            source_row = {
                "LineId": "",
                "Timestamp": "",
                "Content": content,
                "OriginalContent": content,
            }
        cleaned_template = regex_pattern_to_template(regex_template)
        enriched_rows.append(
            [
                source_row["LineId"],
                source_row["Timestamp"],
                source_row["Content"],
                source_row["OriginalContent"],
                event_id,
                cleaned_template,
                regex_template,
            ]
        )
    return enriched_rows


def save_result_rows_with_timestamps(result_rows, out_path, regex_sample):
    if not os.path.exists(out_path):
        os.makedirs(out_path)

    file_path = os.path.join(out_path, f"{regex_sample}.csv")
    with open(file_path, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(
            [
                "LineId",
                "Timestamp",
                "Content",
                "OriginalContent",
                "EventId",
                "RegexTemplate",
                "RegexPattern",
            ]
        )
        writer.writerows(result_rows)

    return file_path


def clean_existing_result_csv(file_path):
    df = pd.read_csv(file_path, dtype=str).fillna("")
    if "RegexTemplate" not in df.columns:
        return False

    if "RegexPattern" not in df.columns:
        df["RegexPattern"] = df["RegexTemplate"]
    else:
        df["RegexPattern"] = df["RegexPattern"].where(
            df["RegexPattern"].astype(str).str.strip() != "",
            df["RegexTemplate"],
        )

    df["RegexTemplate"] = df["RegexPattern"].map(regex_pattern_to_template)
    df.to_csv(file_path, index=False, encoding="utf-8")
    return True


def generate_logformat_regex(logformat):
    """
    Function to generate regular expression to split log messages

    """
    headers = []
    splitters = re.split(r"(<[^<>]+>)", logformat)
    regex = ""
    for k in range(len(splitters)):
        if k % 2 == 0:
            splitter = re.sub(" +", r"\s+", splitters[k])
            regex += splitter
        else:
            header = splitters[k].strip("<").strip(">")
            regex += "(?P<%s>.*?)" % header
            headers.append(header)
    regex = re.compile("^" + regex + "$")
    return headers, regex


def group_logs_using_parser(grouped_logs):
    df = pd.DataFrame(grouped_logs, columns=["Content", "EventId", "EventTemplate"])
    df = df[["Content", "EventId", "EventTemplate"]]
    grouped = df.groupby("EventId")
    groups_dict = {}
    for name, group in grouped:
        groups_dict[name] = group.to_dict("records")
    return groups_dict


def get_logs_from_group(group_list):
    logs_from_group = []
    for ele in group_list:
        logs_from_group.append(ele["Content"])
    return logs_from_group


def check_group_count(groups_dict, removed_items=[]):
    for eventID, logs in list(groups_dict.items()):
        if len(logs) < 5:
            removed_items.extend(
                [[log["Content"], log["EventId"], log["EventTemplate"]] for log in logs]
            )
            del groups_dict[eventID]
    return removed_items, groups_dict


def res_list_to_file(res_list, out_path, regex_sample):
    if not os.path.exists(out_path):
        os.makedirs(out_path)

    file_path = os.path.join(out_path, str(regex_sample) + ".csv")

    file_exists = os.path.isfile(file_path)

    with open(file_path, "a", newline="", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)

        if not file_exists:
            writer.writerow(["Content", "EventId", "RegexTemplate"])

        writer.writerows(res_list)

    return file_path


def one_result_to_file(one_result, out_path):
    if not os.path.exists(out_path):
        os.makedirs(out_path)
    with open(out_path + str(regex_sample) + ".csv", "a", encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(one_result)
    return out_path + str(regex_sample) + ".csv"


def reorder_csv_in_place(csv_path, order_list):
    data = []
    with open(csv_path, mode="r", newline="") as csv_file:
        reader = csv.reader(csv_file)
        header = next(reader) 
        data = list(reader)  

    rows_by_key = {row[0]: row for row in data if row}

    sorted_data = []
    for key in order_list:
        if key in rows_by_key:
            sorted_data.append(rows_by_key[key])

    with open(csv_path, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(header)  
        writer.writerows(sorted_data)  


def prepare_results(output_dir, parser_name, sample_size, list_to_insert, order_list):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    result_file = "summary_[parser={},sample_size={}].csv".format(
        str(parser_name), str(sample_size)
    )
    result_file_path = os.path.join(output_dir, result_file)

    if not os.path.exists(result_file_path) or os.stat(result_file_path).st_size == 0:
        with open(result_file_path, "w", newline="") as csv_file:
            fw = csv.writer(csv_file)
            fw.writerow(
                [
                    "Dataset",
                    "Total_time",
                    "LLaMA_parsing_time",
                    "Drain_parsing_time",
                    "Regex_parsing_time",
                    "GA",
                    "PA",
                    "Event_count",
                ]
            )

    with open(result_file_path, "a", newline="") as csv_file:
        fw = csv.writer(csv_file)
        fw.writerow(list_to_insert)
    reorder_csv_in_place(result_file_path, order_list)
    return result_file


def sort_dict_by_content_length(input_dict):
    def count_words_in_content(entry):
        return len(entry["Content"].split())

    sorted_items = sorted(
        input_dict.items(), key=lambda item: count_words_in_content(item[1][0])
    )

    sorted_dict = {key: value for key, value in sorted_items}
    return sorted_dict


def append_unique_to_csv(data_list, file_path):
    new_data = pd.DataFrame(data_list)
    file = Path(file_path)

    if "Count" in new_data.columns:
        new_data = new_data.drop(columns="Count")
    new_data = new_data.groupby(new_data.columns.tolist(), as_index=False).size()
    new_data = new_data.rename(columns={"size": "Count"})

    if file.is_file():
        existing_data = pd.read_csv(file_path, dtype={1: str})
    else:
        existing_data = pd.DataFrame(columns=new_data.columns)

    combined_data = pd.concat([existing_data, new_data], ignore_index=True)

    combined_data.to_csv(file_path, index=False, header=True)
    return file_path


def discover_raw_log_files(input_root, selectors):
    all_logs = sorted(
        path
        for path in input_root.rglob("*")
        if path.is_file()
        and ".log" in [suffix.lower() for suffix in path.suffixes]
        and "-label.log" not in path.name.lower()
    )

    if not all_logs:
        raise FileNotFoundError(f"No raw .log files found under {input_root}")

    normalized_selectors = [
        selector.strip().replace("\\", "/")
        for selector in selectors
        if selector.strip()
    ]
    if not normalized_selectors or normalized_selectors == ["all"]:
        return all_logs

    matched_logs = []
    seen = set()
    for log_path in all_logs:
        relative_path = log_path.relative_to(input_root).as_posix()
        relative_stem = str(Path(relative_path).with_suffix("")).replace("\\", "/")
        name = log_path.name
        stem = log_path.stem
        parts = {part.lower() for part in log_path.relative_to(input_root).parts}
        for selector in normalized_selectors:
            selector_lower = selector.lower()
            if (
                selector_lower == relative_path.lower()
                or selector_lower == relative_stem.lower()
                or selector_lower == name.lower()
                or selector_lower == stem.lower()
                or selector_lower in relative_path.lower()
                or selector_lower in parts
            ):
                if relative_path not in seen:
                    matched_logs.append(log_path)
                    seen.add(relative_path)
                break

    if not matched_logs:
        selector_text = ", ".join(normalized_selectors)
        raise FileNotFoundError(
            f"No raw .log files matched selectors: {selector_text}"
        )
    return matched_logs


def build_output_dir_for_raw_log(output_root, input_root, log_path):
    relative_path = log_path.relative_to(input_root)
    relative_without_suffix = relative_path.with_suffix("")
    return output_root / relative_without_suffix


def default_raw_grouping_setting():
    return {
        "regex": [
            r"(\d+\.){3}\d+(:\d+)?",
            r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b",
            r"\b[0-9a-fA-F]{8,}\b",
            r"/[^\s,]+",
            r"([\w-]+\.)+[\w-]+",
        ],
        "depth": 4,
        "st": 0.5,
    }


def count_event_templates(result_file):
    if not Path(result_file).is_file():
        return "0"
    df = pd.read_csv(result_file, usecols=["RegexTemplate"])
    return str(df["RegexTemplate"].nunique())


def prepare_raw_results(output_dir, sample_size, list_to_insert):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    result_file = f"summary_raw_[sample_size={sample_size}].csv"
    result_file_path = os.path.join(output_dir, result_file)

    if not os.path.exists(result_file_path) or os.stat(result_file_path).st_size == 0:
        with open(result_file_path, "w", newline="", encoding="utf-8") as csv_file:
            fw = csv.writer(csv_file)
            fw.writerow(
                [
                    "Source",
                    "Total_time",
                    "LLaMA_parsing_time",
                    "Drain_parsing_time",
                    "Regex_parsing_time",
                    "Event_count",
                ]
            )

    with open(result_file_path, "a", newline="", encoding="utf-8") as csv_file:
        fw = csv.writer(csv_file)
        fw.writerow(list_to_insert)
    return result_file


order_list = [
    "HDFS",
    "Hadoop",
    "Spark",
    "Zookeeper",
    "BGL",
    "HPC",
    "Thunderbird",
    "Windows",
    "Linux",
    "Android",
    "HealthApp",
    "Apache",
    "Proxifier",
    "OpenSSH",
    "OpenStack",
    "Mac",
]

def build_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=str, default="all")
    parser.add_argument(
        "--model",
        type=str,
        default=get_env("DEEPSEEK_MODEL", "deepseek-v4-flash"),
    )
    parser.add_argument("--sample", type=int, default=3)
    parser.add_argument("--similarity", type=str, default="jaccard")
    parser.add_argument("--do_self_reflection", type=str, default="True")
    parser.add_argument(
        "--api_key",
        type=str,
        default="",
    )
    parser.add_argument("--api_key_env", type=str, default="")
    parser.add_argument(
        "--api_base",
        type=str,
        default=get_env(
            "DEEPSEEK_BASE_URL",
            "https://api.deepseek.com",
            aliases=("OPENAI_BASE_URL", "LLM_BASE_URL"),
        ),
    )
    parser.add_argument("--api_timeout", type=int, default=120)
    parser.add_argument("--api_retries", type=int, default=5)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max_new_tokens", type=int, default=1024)
    parser.add_argument("--input_dir", type=str, default="full_dataset")
    parser.add_argument("--output_dir", type=str, default="result_deepseek")
    return parser


def resolve_output_dir(output_dir):
    output_path = Path(output_dir)
    if not output_path.is_absolute():
        output_path = REPO_ROOT / output_path
    return output_path


def resolve_input_dir(input_dir):
    input_path = Path(input_dir)
    if not input_path.is_absolute():
        input_path = REPO_ROOT / input_path
    if not input_path.exists() and input_path.name == "full_datasets":
        fallback_path = input_path.with_name("full_dataset")
        if fallback_path.exists():
            return fallback_path
    return input_path


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    selectors = [item.strip() for item in args.project.split(",") if item.strip()]
    model_path = args.model
    similarity = args.similarity
    regex_sample = args.sample
    do_self_reflection = args.do_self_reflection

    try:
        from deepseek_client import DeepSeekClient
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing dependency: openai. Run `pip install -r requirements.txt`."
        ) from exc

    input_root = resolve_input_dir(args.input_dir)
    output_root = resolve_output_dir(args.output_dir)
    try:
        pipeline = DeepSeekClient(
            model=model_path,
            api_key=args.api_key,
            api_key_env=args.api_key_env,
            base_url=args.api_base,
            timeout=args.api_timeout,
            max_retries=args.api_retries,
            temperature=args.temperature,
        )
    except ValueError as exc:
        raise SystemExit(str(exc))
    print(f"{model_path} API client is ready.", flush=True)

    raw_log_files = discover_raw_log_files(input_root, selectors)
    output_root.mkdir(parents=True, exist_ok=True)
    print(
        "Raw .log mode is enabled. `-label.log` files are skipped and GA/PA evaluation is not run.",
        flush=True,
    )

    for log_file in raw_log_files:
        source_name = log_file.relative_to(input_root).as_posix()
        print(f"Start Parsing {source_name}", flush=True)
        out_path = build_output_dir_for_raw_log(output_root, input_root, log_file)
        out_path.mkdir(parents=True, exist_ok=True)
        setting = default_raw_grouping_setting()
        start_time = datetime.now()
        Drain_parser1 = grouping.LogParser(
            rex=setting["regex"],
            depth=setting.get("depth", 4),
            st=setting.get("st", 0.5),
        )
        raw_logs = read_logs_from_plaintext(log_file)
        if not raw_logs:
            print(f"Skip empty log file: {source_name}", flush=True)
            continue
        logs, preprocessed_rows = preprocess_logs(raw_logs)
        save_preprocessed_logs(preprocessed_rows, out_path / "preprocessed.csv")
        extracted_timestamp_count = sum(
            1 for row in preprocessed_rows if row["Timestamp"]
        )
        print(
            f"Timestamp preprocessing finished: {extracted_timestamp_count}/{len(preprocessed_rows)} lines extracted.",
            flush=True,
        )
        grouped_logs = Drain_parser1.parse(logs)
        groups_dict = group_logs_using_parser(grouped_logs)
        groups_dict = sort_dict_by_content_length(groups_dict)
        print("==================", flush=True)
        print(
            "initial set grouping finished, start parsing. ",
            len(groups_dict.keys()),
            " groups in total for ",
            len(logs),
            " logs",
            flush=True,
        )
        print("==================", flush=True)
        regex_manager1 = regex_manager.RegexTemplateManager()
        llama_parser1 = llama_parser.LogParser(
            pipeline=pipeline,
            model=model_path,
            regex_manager1=regex_manager1,
            regex_sample=regex_sample,
            similarity=similarity,
            do_self_reflection=do_self_reflection,
            max_new_tokens=args.max_new_tokens,
        )
        all_results = []
        for eventid in tqdm(groups_dict.keys(), desc=f"Processing events {source_name}"):
            append_unique_to_csv(groups_dict[eventid], str(out_path / "group.csv"))
            res_list = []
            logs_from_group = get_logs_from_group(groups_dict[eventid])
            res_list = llama_parser1.parse(groups_dict[eventid], logs_from_group)
            all_results.extend(res_list)

        result_rows = build_result_rows_with_timestamps(all_results, preprocessed_rows)
        save_result_rows_with_timestamps(
            result_rows, str(out_path), regex_sample=regex_sample
        )

        Drain_parser1.print_time()
        regex_manager1.print_time()
        regex_manager1.print_regex_templates()
        total_time = datetime.now() - start_time
        print(
            source_name + " Parsing done. [Time taken: {!s}]".format(total_time),
            flush=True,
        )
        file_path = out_path / f"{str(regex_sample)}.csv"
        event_count = count_event_templates(file_path)
        print("==================", flush=True)
        print(
            source_name,
            total_time,
            llama_parser1.total_time - regex_manager1.total_time,
            Drain_parser1.total_time,
            regex_manager1.total_time,
            event_count,
            flush=True,
        )
        prepare_raw_results(
            output_dir=str(output_root),
            sample_size=regex_sample,
            list_to_insert=[
                source_name,
                total_time,
                llama_parser1.total_time - regex_manager1.total_time,
                Drain_parser1.total_time,
                regex_manager1.total_time,
                event_count,
            ],
        )
        print("==================", flush=True)


if __name__ == "__main__":
    main()
