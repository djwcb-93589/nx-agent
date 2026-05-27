from agent import compat

compat.ensure_parser_path()

import evaluator


def preprocess_raw_logs(raw_logs):
    return evaluator.preprocess_logs(raw_logs)


def extract_timestamp_and_content(log_line):
    return evaluator.extract_timestamp_and_content(log_line)

