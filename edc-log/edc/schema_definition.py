from typing import List
import os
from pathlib import Path
import edc.utils.llm_utils as llm_utils
import re
from transformers import AutoModelForCausalLM, AutoTokenizer
import logging
from openai import OpenAI
import time

logger = logging.getLogger(__name__)


class SchemaDefiner:
# Schema Definition：给关系生成自然语言定义
    def __init__(
        self,
        model: AutoModelForCausalLM = None,
        tokenizer: AutoTokenizer = None,
        openai_client: OpenAI = None,
        openai_model_id: str = None,
        # 保留旧参数名兼容（如果你别处还传 openai_model）
        openai_model=None,
        max_tokens: int = 512,
        temperature: float = 0.0,
        retry: int = 3,
    ) -> None:
        # 兼容旧的 openai_model={"client":..., "model":...}
        if openai_model is not None and (openai_client is None and openai_model_id is None):
            if isinstance(openai_model, dict):
                openai_client = openai_model.get("client", None)
                openai_model_id = openai_model.get("model", None)
            elif isinstance(openai_model, str):
                # 老逻辑里 openai_model 可能只是模型名
                openai_model_id = openai_model

        assert (openai_client is not None and openai_model_id is not None) or (model is not None and tokenizer is not None)

        self.model = model
        self.tokenizer = tokenizer
        self.openai_client = openai_client
        self.openai_model_id = openai_model_id

        self.max_tokens = max_tokens
        self.temperature = temperature
        self.retry = retry

    def define_schema(
        self,
        input_text_str: str,
        extracted_triplets_list: List[str],
        few_shot_examples_str: str,
        prompt_template_str: str,
    ):
        # 1) 收集关系集合
        relations_present = set()
        for t in extracted_triplets_list:
            relations_present.add(t[1])

        # 可选：为了 prompt 稳定，排序一下
        relations_present_sorted = sorted(list(relations_present))

        # 2) 填 prompt
        filled_prompt = prompt_template_str.format_map(
            {
                "text": input_text_str,
                "few_shot_examples": few_shot_examples_str,
                "relations": relations_present_sorted,     # 用 list 更稳定
                "triples": extracted_triplets_list,
            }
        )
        messages = [{"role": "user", "content": filled_prompt}]

        # 3) 调用：本地 or API
        if self.openai_client is None:
            completion = llm_utils.generate_completion_transformers(
                messages, self.model, self.tokenizer, answer_prepend="Answer: "
            )
        else:
            completion = self._hf_router_chat_completion(messages)

            # 兜底：让 parse_relation_definition 更稳（它一般期待 "Answer:"）
            #if not completion.lstrip().startswith("Answer:"):
                #completion = "Answer: " + completion

        # 4) 解析定义
        relation_definition_dict = llm_utils.parse_relation_definition(completion)

        missing_relations = [rel for rel in relations_present if rel not in relation_definition_dict]
        if len(missing_relations) != 0:
            logger.debug(f"Relations {missing_relations} are missing from the relation definition!")

        return relation_definition_dict

    def _hf_router_chat_completion(self, messages) -> str:
        last_err = None
        for i in range(self.retry):
            try:
                resp = self.openai_client.chat.completions.create(
                    model=self.openai_model_id,
                    messages=messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                return (resp.choices[0].message.content or "").strip()
            except Exception as e:
                last_err = e
                time.sleep(0.8 * (2 ** i))  # 简单退避，抗 429/503
        raise last_err
