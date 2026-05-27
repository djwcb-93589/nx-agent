from pathlib import Path
import json
import os

from agent import compat

compat.ensure_parser_path()

import evaluator


def resolve_input_dir(input_dir):
    return evaluator.resolve_input_dir(input_dir)


def resolve_output_dir(output_dir):
    return evaluator.resolve_output_dir(output_dir)


def parse_selectors(project):
    return [item.strip() for item in project.split(",") if item.strip()]


def discover_raw_logs(input_root, selectors):
    return evaluator.discover_raw_log_files(Path(input_root), selectors)


def source_name(input_root, log_path):
    return Path(log_path).relative_to(input_root).as_posix()


def output_dir_for_source(output_root, input_root, log_path):
    return evaluator.build_output_dir_for_raw_log(
        Path(output_root), Path(input_root), Path(log_path)
    )


def read_plaintext_logs(log_path):
    logs = []
    with open(log_path, mode="r", encoding="utf-8-sig", errors="replace") as file:
        for line in file:
            content = line.rstrip("\r\n")
            if content.strip():
                logs.append(content)
    return logs


def save_preprocessed_rows(rows, out_path):
    return evaluator.save_preprocessed_logs(rows, Path(out_path) / "preprocessed.csv")


def append_group_records(records, out_path):
    return evaluator.append_unique_to_csv(records, str(Path(out_path) / "group.csv"))


def build_result_rows(parsed_results, preprocessed_rows):
    return evaluator.build_result_rows_with_timestamps(parsed_results, preprocessed_rows)


def save_result_rows(result_rows, out_path, sample_size):
    return evaluator.save_result_rows_with_timestamps(
        result_rows, str(out_path), regex_sample=sample_size
    )


def count_event_templates(result_file):
    return evaluator.count_event_templates(result_file)


def write_raw_summary(output_root, sample_size, row):
    return evaluator.prepare_raw_results(
        output_dir=str(output_root), sample_size=sample_size, list_to_insert=row
    )


def save_group_tree(group_tree, out_path):
    path = Path(out_path) / "group_tree.json"
    with open(path, "w", encoding="utf-8") as file:
        json.dump(group_tree, file, indent=2, ensure_ascii=False)
    return path


def clean_source_outputs(out_path, sample_size, include_tree=True):
    out_path = Path(out_path)
    if not out_path.exists():
        return
    targets = [
        out_path / "preprocessed.csv",
        out_path / "group.csv",
        out_path / f"{sample_size}.csv",
        out_path / "poi_schema.csv",
        out_path / "relation_schema.csv",
        out_path / "schema_meta.json",
    ]
    if include_tree:
        targets.append(out_path / "group_tree.json")
    for target in targets:
        if target.is_file():
            os.remove(target)


def clean_run_summary(output_root, sample_size):
    target = Path(output_root) / f"summary_raw_[sample_size={sample_size}].csv"
    if target.is_file():
        os.remove(target)
