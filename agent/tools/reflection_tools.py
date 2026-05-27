from datetime import datetime
import re

from agent.tools import llm_tools, memory_tools, regex_tools


def check_pre_logs(template_engine, logs, records=False):
    return template_engine.check_pre_logs(logs, dic=records)


def parse_group_with_tools(template_engine, group_records, logs):
    start_time = datetime.now()
    results = []
    logs = list(logs)

    if check_pre_logs(template_engine, logs, records=False):
        regex_pattern = re.escape(logs[0]).replace(r"\ ", " ")
        results = store_regex_for_logs(template_engine, results, group_records, regex_pattern)
    else:
        for log in logs[::-1]:
            matched_regex = memory_tools.find_matching_regex(
                template_engine.regex_manager1, log
            )
            if matched_regex:
                logs.remove(log)
                group_records = _remove_first_matching_item(group_records, log)
                results.append([log, "0", matched_regex])
        if logs:
            regex_pattern = llm_tools.generate_log_regex(
                template_engine, log_list=logs, records=False
            )
            results = store_regex_for_logs(
                template_engine, results, group_records, regex_pattern
            )

    template_engine.total_time += (datetime.now() - start_time).total_seconds()
    return results


def store_regex_for_logs(template_engine, results, group_records, regex_pattern):
    results, wrong_logs = check_regex_from_group(
        template_engine, results, group_records, regex_pattern
    )
    previous_wrong_count = len(wrong_logs)
    test_time = 0

    while (
        len(wrong_logs) > 0
        and test_time < 3
        and previous_wrong_count == len(wrong_logs)
    ):
        previous_wrong_count = len(wrong_logs)
        test_time += 1
        regex_pattern = llm_tools.generate_log_regex(
            template_engine, log_list=wrong_logs, records=True
        )
        results, wrong_logs = check_regex_from_group(
            template_engine,
            results,
            wrong_logs,
            regex_pattern,
            template_engine.new_event,
        )
        if previous_wrong_count != len(wrong_logs):
            template_engine.new_event += 1

    for log in wrong_logs:
        results.append((log["Content"], template_engine.new_event, regex_pattern))
        template_engine.new_event += 1
    return results


def check_regex_from_group(
    template_engine, results, group_records, regex_pattern, new_event=0
):
    wrong_logs = []
    for log in group_records:
        if template_engine.do_self_reflection == "True":
            if regex_tools.verify_regex(log["Content"], regex_pattern):
                memory_tools.add_regex(
                    template_engine.regex_manager1, regex_pattern, log["Content"]
                )
                if new_event == 0:
                    results.append((log["Content"], log["EventId"], regex_pattern))
                else:
                    results.append((log["Content"], new_event, regex_pattern))
            else:
                wrong_logs.append(log)
        else:
            if regex_tools.verify_regex(log["Content"], regex_pattern):
                memory_tools.add_regex(
                    template_engine.regex_manager1, regex_pattern, log["Content"]
                )
            results.append((log["Content"], log["EventId"], regex_pattern))
    return results, wrong_logs


def _remove_first_matching_item(records, content_to_remove):
    for index, item in enumerate(records):
        if item["Content"] == content_to_remove:
            del records[index]
            break
    return records

