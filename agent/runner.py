import argparse
from datetime import datetime
from pathlib import Path

from tqdm import tqdm

from agent import compat
from agent.defaults import DEFAULT_LLM_API_KEY, DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL_ID
from agent.planner import DeepSeekPlanner
from agent.state import AgentConfig, AgentRunResult, SourceRunResult
from agent.template_engine import AgentTemplateEngine
from agent.trace import TraceRecorder
from agent.tools import (
    grouping_tools,
    io_tools,
    llm_tools,
    memory_tools,
    preprocess_tools,
    reflection_tools,
    sampling_tools,
    schema_tools,
)

compat.ensure_parser_path()


class LibreLogAgent:
    def __init__(self, config):
        self.config = config
        self.pipeline = llm_tools.create_llm_client(config)
        self.planner = DeepSeekPlanner(
            self.pipeline,
            enabled=config.planner_enabled,
            max_tokens=min(config.max_new_tokens, 2048),
        )
        self.trace = TraceRecorder(enabled=True)

    def run(self):
        input_root = io_tools.resolve_input_dir(self.config.input_dir)
        output_root = io_tools.resolve_output_dir(self.config.output_dir)
        selectors = io_tools.parse_selectors(self.config.project)
        raw_log_files = io_tools.discover_raw_logs(input_root, selectors)
        output_root.mkdir(parents=True, exist_ok=True)
        if self.config.overwrite:
            io_tools.clean_run_summary(output_root, self.config.sample)

        print(
            "Agent raw .log mode is enabled. `-label.log` files are skipped and GA/PA evaluation is not run.",
            flush=True,
        )
        result = AgentRunResult(input_root=input_root, output_root=output_root)
        for log_file in raw_log_files:
            result.sources.append(self.run_source(input_root, output_root, log_file))
        return result

    def run_source(self, input_root, output_root, log_file):
        source = io_tools.source_name(input_root, log_file)
        out_path = io_tools.output_dir_for_source(output_root, input_root, log_file)
        out_path.mkdir(parents=True, exist_ok=True)
        if self.config.overwrite:
            io_tools.clean_source_outputs(out_path, self.config.sample)

        print(f"Start Agent Parsing {source}", flush=True)
        start_time = datetime.now()
        context = {
            "source": source,
            "input_root": input_root,
            "output_root": output_root,
            "log_file": log_file,
            "out_path": out_path,
            "raw_logs": None,
            "logs": None,
            "preprocessed_rows": None,
            "schema_info": None,
            "drain_parser": None,
            "groups_dict": None,
            "group_tree": None,
            "regex_memory": None,
            "template_engine": None,
            "all_results": [],
            "result_file": out_path / f"{self.config.sample}.csv",
        }

        raw_preview = self._read_raw_preview(log_file, limit=5)
        schema_hint = schema_tools.infer_schema_type(
            source,
            schema_tools.resolve_schemas_dir(
                self.config.schemas_dir, compat.REPO_ROOT
            ),
        )
        plan = self.planner.plan_source(
            source_name=source,
            raw_preview=raw_preview,
            schema_hint=schema_hint,
            config=self.config,
        )
        self.trace.emit(
            "plan",
            "deepseek_planner",
            "DeepSeek 已生成本日志源的工具调度计划。",
            source=source,
            notes=plan.get("notes", ""),
            actions=plan.get("actions", []),
        )

        for action in plan["actions"]:
            tool = action["tool"]
            self.trace.emit(
                "dispatch",
                tool,
                action.get("reason") or "执行工具。",
                source=source,
            )
            self._execute_tool_action(tool, context)

        drain_parser = context["drain_parser"]
        regex_memory = context["regex_memory"]
        logs = context["logs"] or []
        groups_dict = context["groups_dict"] or {}
        group_tree = context["group_tree"]
        result_file = Path(context["result_file"])

        if drain_parser:
            drain_parser.print_time()
        if regex_memory:
            regex_memory.print_time()
        total_time = datetime.now() - start_time
        event_count = io_tools.count_event_templates(result_file)
        template_engine = context["template_engine"]
        llm_time = (
            template_engine.total_time - regex_memory.total_time
            if template_engine and regex_memory
            else 0.0
        )

        print(
            source + " Agent parsing done. [Time taken: {!s}]".format(total_time),
            flush=True,
        )
        print("==================", flush=True)
        print(
            source,
            total_time,
            llm_time,
            drain_parser.total_time if drain_parser else 0.0,
            regex_memory.total_time if regex_memory else 0.0,
            event_count,
            flush=True,
        )
        io_tools.write_raw_summary(
            output_root,
            self.config.sample,
            [
                source,
                total_time,
                llm_time,
                drain_parser.total_time if drain_parser else 0.0,
                regex_memory.total_time if regex_memory else 0.0,
                event_count,
            ],
        )
        self.trace.emit(
            "complete",
            "source_run",
            "日志源解析完成。",
            source=source,
            event_count=event_count,
            total_time=str(total_time),
        )
        print("==================", flush=True)

        return SourceRunResult(
            source=source,
            output_dir=out_path,
            result_file=result_file,
            total_time=total_time,
            llm_parsing_time=llm_time,
            grouping_time=drain_parser.total_time if drain_parser else 0.0,
            regex_matching_time=regex_memory.total_time if regex_memory else 0.0,
            event_count=event_count,
            line_count=len(logs),
            group_count=len(groups_dict),
            tree=group_tree if self.config.write_group_tree else None,
        )

    def _execute_tool_action(self, tool, context):
        if tool == "read_raw_logs":
            raw_logs = io_tools.read_plaintext_logs(context["log_file"])
            context["raw_logs"] = raw_logs
            self.trace.emit(
                "observe",
                tool,
                "原始日志读取完成。",
                source=context["source"],
                line_count=len(raw_logs),
            )
            if not raw_logs:
                print(f"Skip empty log file: {context['source']}", flush=True)
            return

        if tool == "preprocess_logs":
            raw_logs = context["raw_logs"] or []
            logs, preprocessed_rows = preprocess_tools.preprocess_raw_logs(raw_logs)
            context["logs"] = logs
            context["preprocessed_rows"] = preprocessed_rows
            io_tools.save_preprocessed_rows(preprocessed_rows, context["out_path"])
            extracted_timestamp_count = sum(
                1 for row in preprocessed_rows if row["Timestamp"]
            )
            print(
                f"Timestamp preprocessing finished: {extracted_timestamp_count}/{len(preprocessed_rows)} lines extracted.",
                flush=True,
            )
            self.trace.emit(
                "observe",
                tool,
                "时间戳预处理完成。",
                source=context["source"],
                line_count=len(preprocessed_rows),
                timestamp_count=extracted_timestamp_count,
            )
            return

        if tool == "ensure_schema":
            schemas_dir = schema_tools.resolve_schemas_dir(
                self.config.schemas_dir, compat.REPO_ROOT
            )
            schema_info = schema_tools.ensure_schema_for_source(
                source_name=context["source"],
                logs=context["logs"] or [],
                pipeline=self.pipeline,
                schemas_dir=schemas_dir,
                out_path=context["out_path"],
                sample_size=max(self.config.sample, 8),
            )
            context["schema_info"] = schema_info
            self.trace.emit(
                "observe",
                tool,
                "POI/relation schema 已准备完成。",
                source=context["source"],
                **schema_info,
            )
            return

        if tool == "build_deep_group_tree":
            grouping_setting = grouping_tools.default_raw_grouping_setting()
            drain_parser, groups_dict, group_tree = grouping_tools.build_deep_group_tree(
                context["logs"] or [], grouping_setting
            )
            context["drain_parser"] = drain_parser
            context["groups_dict"] = groups_dict
            context["group_tree"] = group_tree
            if self.config.write_group_tree:
                io_tools.save_group_tree(group_tree, context["out_path"])
            print("==================", flush=True)
            print(
                "deep grouping tree finished, start agent parsing. ",
                len(groups_dict.keys()),
                " groups in total for ",
                len(context["logs"] or []),
                " logs",
                flush=True,
            )
            print("==================", flush=True)
            self.trace.emit(
                "observe",
                tool,
                "深度分组树构建完成。",
                source=context["source"],
                group_count=len(groups_dict),
                line_count=len(context["logs"] or []),
            )
            return

        if tool == "parse_groups_with_memory_reflection":
            regex_memory = memory_tools.create_regex_memory()
            template_engine = AgentTemplateEngine(
                pipeline=self.pipeline,
                model=self.config.model,
                regex_manager1=regex_memory,
                regex_sample=self.config.sample,
                similarity=self.config.similarity,
                do_self_reflection=self.config.do_self_reflection,
                max_new_tokens=self.config.max_new_tokens,
            )
            context["regex_memory"] = regex_memory
            context["template_engine"] = template_engine
            all_results = []
            groups_dict = context["groups_dict"] or {}
            for index, event_id in enumerate(
                tqdm(groups_dict.keys(), desc=f"Agent events {context['source']}"),
                start=1,
            ):
                group_records = groups_dict[event_id]
                logs_from_group = grouping_tools.get_logs_from_group(group_records)
                group_strategy = self.planner.plan_group(
                    source_name=context["source"],
                    event_id=event_id,
                    sample_logs=sampling_tools.select_representative_logs(
                        logs_from_group,
                        sample_size=min(self.config.sample, 3),
                        metric=self.config.similarity,
                        max_logs=50,
                    ),
                    group_size=len(group_records),
                    memory_size=len(regex_memory.regex_templates),
                    schema_info=context.get("schema_info") or {},
                    config=self.config,
                )
                self.trace.emit(
                    "dispatch",
                    "group_planner",
                    "DeepSeek 已为事件组选择解析策略。",
                    source=context["source"],
                    event_id=event_id,
                    group_index=index,
                    group_size=len(group_records),
                    strategy=group_strategy,
                )
                io_tools.append_group_records(group_records, context["out_path"])
                old_similarity = template_engine.similarity
                old_reflection = template_engine.do_self_reflection
                template_engine.similarity = group_strategy.get(
                    "similarity", old_similarity
                )
                template_engine.do_self_reflection = (
                    "True" if group_strategy.get("use_reflection", True) else "False"
                )
                parsed_group = reflection_tools.parse_group_with_tools(
                    template_engine, group_records, logs_from_group
                )
                template_engine.similarity = old_similarity
                template_engine.do_self_reflection = old_reflection
                all_results.extend(parsed_group)
                self.trace.emit(
                    "observe",
                    "parse_group",
                    "事件组解析完成。",
                    source=context["source"],
                    event_id=event_id,
                    parsed_rows=len(parsed_group),
                    memory_size=len(regex_memory.regex_templates),
                )
            context["all_results"] = all_results
            return

        if tool == "write_outputs":
            result_rows = io_tools.build_result_rows(
                context["all_results"], context["preprocessed_rows"] or []
            )
            result_file = Path(
                io_tools.save_result_rows(
                    result_rows, context["out_path"], self.config.sample
                )
            )
            context["result_file"] = result_file
            self.trace.emit(
                "observe",
                tool,
                "解析结果 CSV 已写入。",
                source=context["source"],
                result_file=str(result_file),
                row_count=len(result_rows),
            )
            return

        raise ValueError(f"Unknown agent tool: {tool}")

    def _read_raw_preview(self, log_file, limit=5):
        preview = []
        with open(log_file, "r", encoding="utf-8-sig", errors="replace") as file:
            for index, line in enumerate(file, start=1):
                if index > limit:
                    break
                if line.strip():
                    preview.append(line.rstrip("\r\n"))
        return preview


def build_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=str, default="all")
    parser.add_argument("--model", type=str, default=DEFAULT_LLM_MODEL_ID)
    parser.add_argument("--sample", type=int, default=3)
    parser.add_argument("--similarity", type=str, default="jaccard")
    parser.add_argument("--do_self_reflection", type=str, default="True")
    parser.add_argument("--api_key", type=str, default=DEFAULT_LLM_API_KEY)
    parser.add_argument("--api_key_env", type=str, default="DEEPSEEK_API_KEY")
    parser.add_argument("--api_base", type=str, default=DEFAULT_LLM_BASE_URL)
    parser.add_argument("--api_timeout", type=int, default=120)
    parser.add_argument("--api_retries", type=int, default=5)
    parser.add_argument("--reasoning_effort", type=str, default="high")
    parser.add_argument("--disable_thinking", action="store_true")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max_new_tokens", type=int, default=1024)
    parser.add_argument("--input_dir", type=str, default="full_dataset")
    parser.add_argument("--output_dir", type=str, default="result_deepseek")
    parser.add_argument("--schemas_dir", type=str, default="schemas")
    parser.add_argument("--write_group_tree", action="store_true")
    parser.add_argument("--disable_planner", action="store_true")
    parser.add_argument(
        "--preserve_existing",
        action="store_true",
        help="Do not clean per-source output CSV files before writing new results.",
    )
    parser.add_argument(
        "--mock_llm",
        action="store_true",
        help="Use the offline heuristic client for smoke tests.",
    )
    return parser


def config_from_args(args):
    return AgentConfig(
        project=args.project,
        model=args.model,
        sample=args.sample,
        similarity=args.similarity,
        do_self_reflection=args.do_self_reflection,
        api_key=args.api_key,
        api_key_env=args.api_key_env,
        api_base=args.api_base,
        api_timeout=args.api_timeout,
        api_retries=args.api_retries,
        reasoning_effort=args.reasoning_effort,
        thinking_enabled=not args.disable_thinking,
        temperature=args.temperature,
        max_new_tokens=args.max_new_tokens,
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        schemas_dir=args.schemas_dir,
        write_group_tree=args.write_group_tree,
        overwrite=not args.preserve_existing,
        mock_llm=args.mock_llm,
        planner_enabled=not args.disable_planner,
    )


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    agent = LibreLogAgent(config_from_args(args))
    agent.run()


if __name__ == "__main__":
    main()
