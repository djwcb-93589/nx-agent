from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import json
from typing import Any

from .config import QueryAgentConfig
from .cypher_guard import ensure_read_only_cypher
from .deepseek_client import DeepSeekClient
from .neo4j_client import Neo4jGraphClient, QueryExecutionResult
from .prompts import (
    build_answer_system_prompt,
    build_answer_user_prompt,
    build_cypher_repair_prompt,
    build_cypher_system_prompt,
    build_cypher_user_prompt,
)
from .schema import GraphSchema, load_graph_schema, save_graph_schema
from .serializers import serialize_rows


@dataclass(frozen=True)
class CypherPlan:
    subquestions: list[str]
    schema_elements_used: dict[str, list[str]]
    world_knowledge_notes: list[str]
    cypher: str
    parameters: dict[str, Any]
    result_focus: str


@dataclass(frozen=True)
class QueryAnswer:
    schema: GraphSchema
    plan: CypherPlan
    rows: list[dict[str, Any]]
    truncated: bool
    answer: str


class QueryAgent:
    def __init__(self, config: QueryAgentConfig) -> None:
        self.config = config
        self.llm_client = DeepSeekClient(config.llm)

    def with_runtime_overrides(
        self,
        *,
        max_result_rows: int | None = None,
        max_answer_rows: int | None = None,
    ) -> "QueryAgent":
        runtime = self.config.runtime
        updated_runtime = replace(
            runtime,
            max_result_rows=runtime.max_result_rows if max_result_rows is None else max_result_rows,
            max_answer_rows=runtime.max_answer_rows if max_answer_rows is None else max_answer_rows,
        )
        return QueryAgent(replace(self.config, runtime=updated_runtime))

    def load_schema(self, *, refresh: bool = False) -> GraphSchema:
        cache_path = self.config.runtime.schema_cache_path
        if cache_path.exists() and not refresh and not self.config.runtime.auto_refresh_schema:
            return load_graph_schema(cache_path)

        with Neo4jGraphClient(self.config.neo4j) as graph:
            schema = graph.extract_schema()
        save_graph_schema(schema, cache_path)
        return schema

    def run(self, question: str, *, refresh_schema: bool = False) -> QueryAnswer:
        schema = self.load_schema(refresh=refresh_schema or self.config.runtime.auto_refresh_schema)
        schema_text = schema.to_prompt_text()
        plan = self._generate_cypher_plan(question=question, schema=schema, schema_text=schema_text)

        for attempt in range(self.config.runtime.max_repair_attempts + 1):
            try:
                execution = self._execute_plan(plan)
                answer_text = self._generate_answer(
                    question=question,
                    plan=plan,
                    execution=execution,
                )
                result = QueryAnswer(
                    schema=schema,
                    plan=plan,
                    rows=execution.rows,
                    truncated=execution.truncated,
                    answer=answer_text,
                )
                self._save_run_artifacts(question=question, result=result)
                return result
            except Exception as exc:
                if attempt >= self.config.runtime.max_repair_attempts:
                    raise
                plan = self._repair_cypher_plan(
                    question=question,
                    schema=schema,
                    schema_text=schema_text,
                    previous_plan=plan,
                    error_message=str(exc),
                )

        raise RuntimeError("Query execution failed")

    def _generate_cypher_plan(
        self,
        *,
        question: str,
        schema: GraphSchema,
        schema_text: str,
    ) -> CypherPlan:
        payload = self.llm_client.chat_json(
            messages=[
                {
                    "role": "system",
                    "content": build_cypher_system_prompt(
                        schema_text,
                        self.config.runtime.max_result_rows,
                    ),
                },
                {"role": "user", "content": build_cypher_user_prompt(question)},
            ],
            model=self.config.llm.cypher_model,
        )
        return self._parse_plan_payload(payload=payload, schema=schema)

    def _repair_cypher_plan(
        self,
        *,
        question: str,
        schema: GraphSchema,
        schema_text: str,
        previous_plan: CypherPlan,
        error_message: str,
    ) -> CypherPlan:
        payload = self.llm_client.chat_json(
            messages=[
                {
                    "role": "system",
                    "content": build_cypher_system_prompt(
                        schema_text,
                        self.config.runtime.max_result_rows,
                    ),
                },
                {
                    "role": "user",
                    "content": build_cypher_repair_prompt(
                        schema_text=schema_text,
                        question=question,
                        previous_cypher=previous_plan.cypher,
                        previous_parameters=previous_plan.parameters,
                        error_message=error_message,
                        max_result_rows=self.config.runtime.max_result_rows,
                    ),
                },
            ],
            model=self.config.llm.cypher_model,
        )
        return self._parse_plan_payload(payload=payload, schema=schema)

    def _parse_plan_payload(self, *, payload: dict[str, Any], schema: GraphSchema) -> CypherPlan:
        subquestions = [str(item).strip() for item in payload.get("subquestions", []) if str(item).strip()]
        world_knowledge_notes = [
            str(item).strip() for item in payload.get("world_knowledge_notes", []) if str(item).strip()
        ]
        schema_elements_raw = payload.get("schema_elements_used") or {}
        schema_elements_used = {
            "labels": [str(item).strip() for item in schema_elements_raw.get("labels", []) if str(item).strip()],
            "relationship_types": [
                str(item).strip()
                for item in schema_elements_raw.get("relationship_types", [])
                if str(item).strip()
            ],
            "properties": [
                str(item).strip()
                for item in schema_elements_raw.get("properties", [])
                if str(item).strip()
            ],
        }
        cypher = ensure_read_only_cypher(str(payload.get("cypher", "")))
        parameters = payload.get("parameters") or {}
        if not isinstance(parameters, dict):
            raise ValueError("Generated parameters must be a JSON object")
        result_focus = str(payload.get("result_focus", "")).strip()

        self._validate_schema_claims(schema=schema, schema_elements_used=schema_elements_used)

        return CypherPlan(
            subquestions=subquestions,
            schema_elements_used=schema_elements_used,
            world_knowledge_notes=world_knowledge_notes,
            cypher=cypher,
            parameters=parameters,
            result_focus=result_focus,
        )

    @staticmethod
    def _validate_schema_claims(schema: GraphSchema, schema_elements_used: dict[str, list[str]]) -> None:
        unknown_labels = sorted(set(schema_elements_used.get("labels", [])) - schema.labels)
        unknown_rels = sorted(set(schema_elements_used.get("relationship_types", [])) - schema.relationship_types)
        unknown_props = sorted(set(schema_elements_used.get("properties", [])) - schema.property_names)

        if unknown_labels:
            raise ValueError(f"Generated plan referenced labels outside schema: {unknown_labels}")
        if unknown_rels:
            raise ValueError(f"Generated plan referenced relationship types outside schema: {unknown_rels}")
        if unknown_props:
            raise ValueError(f"Generated plan referenced properties outside schema: {unknown_props}")

    def _execute_plan(self, plan: CypherPlan) -> QueryExecutionResult:
        with Neo4jGraphClient(self.config.neo4j) as graph:
            return graph.run_read_query(
                cypher=plan.cypher,
                parameters=plan.parameters,
                max_rows=self.config.runtime.max_result_rows,
            )

    def _generate_answer(
        self,
        *,
        question: str,
        plan: CypherPlan,
        execution: QueryExecutionResult,
    ) -> str:
        rows_for_answer = execution.rows[: self.config.runtime.max_answer_rows]
        rows_json = json.dumps(serialize_rows(rows_for_answer), ensure_ascii=False, indent=2)
        return self.llm_client.chat_text(
            messages=[
                {"role": "system", "content": build_answer_system_prompt()},
                {
                    "role": "user",
                    "content": build_answer_user_prompt(
                        question=question,
                        cypher=plan.cypher,
                        parameters=plan.parameters,
                        row_count=len(execution.rows),
                        truncated=execution.truncated,
                        rows_json=rows_json,
                    ),
                },
            ],
            model=self.config.llm.answer_model,
        )

    def _save_run_artifacts(self, *, question: str, result: QueryAnswer) -> None:
        output_dir = self.config.runtime.run_output_dir
        if output_dir is None:
            return

        output_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = output_dir / f"query_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        payload = {
            "question": question,
            "subquestions": result.plan.subquestions,
            "schema_elements_used": result.plan.schema_elements_used,
            "world_knowledge_notes": result.plan.world_knowledge_notes,
            "cypher": result.plan.cypher,
            "parameters": result.plan.parameters,
            "result_focus": result.plan.result_focus,
            "row_count": len(result.rows),
            "truncated": result.truncated,
            "rows": serialize_rows(result.rows),
            "answer": result.answer,
        }
        with artifact_path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, ensure_ascii=False)
            file.write("\n")

