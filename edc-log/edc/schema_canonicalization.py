from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterable

from openai import OpenAI


logger = logging.getLogger(__name__)


class SchemaCanonicalizer:
    """Map extracted log fields to the current POI schema using DeepSeek only."""

    def __init__(
        self,
        target_schema_dict: dict[str, str],
        *,
        verify_openai_client: OpenAI,
        verify_openai_model_id: str,
        max_tokens: int = 512,
        temperature: float = 0.0,
        retry: int = 3,
    ) -> None:
        if verify_openai_client is None or not verify_openai_model_id:
            raise ValueError("DeepSeek client and model id are required for schema mapping.")
        self.schema_dict = target_schema_dict
        self.verifier_openai_client = verify_openai_client
        self.verifier_openai_model_id = verify_openai_model_id
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.retry = retry

    def canonicalize_fields(
        self,
        input_text_str: str,
        open_relation_definition_dict: dict[str, str],
        prompt_template_str: str,
    ) -> tuple[dict[str, str | None], dict[str, str]]:
        if not self.schema_dict:
            return {field: None for field in open_relation_definition_dict}, {}

        source_fields = list(open_relation_definition_dict.keys())
        canonical_fields_txt = "\n".join(
            f"- {field}: {description}" for field, description in self.schema_dict.items()
        )
        canonical_fields_txt += "\n- NONE: No suitable canonical mapping for strict alignment."
        source_fields_txt = "\n".join(
            f"- {field}: {open_relation_definition_dict[field]}" for field in source_fields
        )

        prompt = prompt_template_str.format_map(
            {
                "input_text": input_text_str,
                "source_fields": source_fields_txt,
                "canonical_fields": canonical_fields_txt,
            }
        )
        completion = self._deepseek_chat([{"role": "user", "content": prompt}])
        mapping = parse_field_mapping(completion, source_fields, self.schema_dict.keys())
        return mapping, self.schema_dict

    # Kept for existing callers. This method now performs the same DeepSeek-only
    # semantic mapping as canonicalize_fields.
    def canonicalize1(
        self,
        input_text_str: str,
        open_relation_definition_dict: dict[str, str],
        verify_prompt_template: str,
        enrich: bool = False,
    ) -> tuple[dict[str, str | None], dict[str, str]]:
        return self.canonicalize_fields(
            input_text_str,
            open_relation_definition_dict,
            verify_prompt_template,
        )

    def _deepseek_chat(self, messages: list[dict[str, str]]) -> str:
        last_err: Exception | None = None
        for attempt in range(self.retry):
            try:
                response = self.verifier_openai_client.chat.completions.create(
                    model=self.verifier_openai_model_id,
                    messages=messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                return (response.choices[0].message.content or "").strip()
            except Exception as exc:
                last_err = exc
                time.sleep(0.8 * (2**attempt))
        raise last_err  # type: ignore[misc]


def parse_field_mapping(
    completion: str,
    source_fields: Iterable[str],
    canonical_fields: Iterable[str],
) -> dict[str, str | None]:
    """Parse DeepSeek lines like `source_field -> canonical_field`."""
    source_lookup = {field.casefold(): field for field in source_fields}
    canonical_lookup = {field.casefold(): field for field in canonical_fields}
    mapping: dict[str, str | None] = {field: None for field in source_lookup.values()}

    for raw_line in completion.splitlines():
        line = raw_line.strip()
        if not line or "->" not in line:
            continue
        left, right = line.split("->", 1)
        src = _clean_mapping_token(left)
        dst = _clean_mapping_token(right)
        src_key = src.casefold()
        if src_key not in source_lookup:
            continue
        if dst.casefold() == "none":
            mapping[source_lookup[src_key]] = None
            continue
        dst_key = dst.casefold()
        if dst_key in canonical_lookup:
            mapping[source_lookup[src_key]] = canonical_lookup[dst_key]
    return mapping


def _clean_mapping_token(value: str) -> str:
    text = value.strip().strip("`'\"")
    text = re.sub(r"^[-*]\s+", "", text)
    text = re.sub(r"^\d+[.)]\s+", "", text)
    text = text.strip().strip(" .,:;`'\"")
    return text
