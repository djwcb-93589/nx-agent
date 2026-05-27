from agent import compat

compat.ensure_parser_path()

import regex_manager


def create_regex_memory():
    return regex_manager.RegexTemplateManager()


def find_matching_regex(memory, log):
    return memory.find_matched_regex_template(log)


def add_regex(memory, regex_pattern, matched_log):
    return memory.add_regex_template(regex_pattern, matched_log)


def snapshot(memory):
    return [
        {"word_count": word_count, "regex": regex_pattern}
        for word_count, regex_pattern in memory.regex_templates
    ]

