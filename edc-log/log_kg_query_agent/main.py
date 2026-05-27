from __future__ import annotations

import argparse

from query_agent.config import load_query_agent_config
from query_agent.engine import QueryAgent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LLM-powered query agent for the Neo4j log knowledge graph.",
    )
    parser.add_argument("--config", required=True, help="Path to query agent JSON config")
    parser.add_argument("--question", help="Natural-language security question")
    parser.add_argument("--refresh-schema", action="store_true", help="Refresh schema cache from Neo4j")
    parser.add_argument("--schema-only", action="store_true", help="Only load and print schema, then exit")
    parser.add_argument("--max-result-rows", type=int, help="Override runtime max_result_rows")
    parser.add_argument("--max-answer-rows", type=int, help="Override runtime max_answer_rows")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_query_agent_config(
        args.config,
        require_llm_api_key=not args.schema_only,
    )
    agent = QueryAgent(config).with_runtime_overrides(
        max_result_rows=args.max_result_rows,
        max_answer_rows=args.max_answer_rows,
    )

    if args.schema_only:
        schema = agent.load_schema(refresh=args.refresh_schema)
        print(schema.to_prompt_text())
        print(f"\nSchema cache: {agent.config.runtime.schema_cache_path}")
        return

    if not args.question:
        raise ValueError("--question is required unless --schema-only is used")

    result = agent.run(args.question, refresh_schema=args.refresh_schema)

    print("Cypher plan")
    print(f"- subquestions: {result.plan.subquestions}")
    print(f"- schema_elements_used: {result.plan.schema_elements_used}")
    print(f"- world_knowledge_notes: {result.plan.world_knowledge_notes}")
    print(f"- result_focus: {result.plan.result_focus}")
    print("\nCypher")
    print(result.plan.cypher)
    print("\nParameters")
    print(result.plan.parameters)
    print(f"\nRows returned: {len(result.rows)}")
    if result.truncated:
        print("Result rows were truncated at the configured limit.")
    print("\nAnswer")
    print(result.answer)


if __name__ == "__main__":
    main()
