from agent import compat

compat.ensure_parser_path()

import evaluator
import llama_parser
import regex_manager


def verify_regex(log, regex_pattern):
    return llama_parser.verify_one_regex(log, regex_pattern)


def verify_regex_whole_log(log, regex_pattern):
    return regex_manager.verify_one_regex_to_match_whole_log(log, regex_pattern)


def regex_pattern_to_template(regex_pattern):
    return evaluator.regex_pattern_to_template(regex_pattern)


def template_to_regex(template_engine, template):
    return template_engine.template_to_regex(template)


def clean_regex(template_engine, log, regex_pattern):
    return template_engine.clean_regex(log=log, regex=regex_pattern)

