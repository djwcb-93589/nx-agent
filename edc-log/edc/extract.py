from typing import List
import os
from pathlib import Path
import edc.utils.llm_utils as llm_utils
import re
from transformers import AutoModelForCausalLM, AutoTokenizer
import json

import time
from typing import List
from openai import OpenAI
from transformers import AutoModelForCausalLM, AutoTokenizer

class Extractor:
    # The class to handle the first stage: Open Information Extraction
    def __init__(
        self,
        model: AutoModelForCausalLM = None,
        tokenizer: AutoTokenizer = None,
        openai_client: OpenAI = None,
        openai_model_id: str = None,
        # 兼容你旧参数名 openai_model：允许传 {"client":..., "model":...}
        openai_model=None,
        max_tokens: int = 512,
        temperature: float = 0.0,
        retry: int = 3,
    ) -> None:
        # 兼容：如果传了 openai_model={"client":..., "model":...}
        if openai_model is not None and (openai_client is None and openai_model_id is None):
            if isinstance(openai_model, dict):
                openai_client = openai_model.get("client", None)
                openai_model_id = openai_model.get("model", None)

        assert (openai_client is not None and openai_model_id is not None) or (model is not None and tokenizer is not None)

        self.model = model
        self.tokenizer = tokenizer
        self.openai_client = openai_client
        self.openai_model_id = openai_model_id

        self.max_tokens = max_tokens
        self.temperature = temperature
        self.retry = retry

    def extract(
        self,
        input_text_str: str,
        prompt_template_str: str,
    ) -> List[List[str]]:

        def unescape_latex(s: str) -> str:
            # 只处理你关心的几类，避免过度替换
            return (s.replace(r"\_", "_")
                    .replace(r"\-", "-")
                    .replace(r"\&", "&")
                    .replace(r"\%", "%")
                    .replace(r"\#", "#"))

        filled_prompt = prompt_template_str.format_map({"input_text": input_text_str})

        messages = [{"role": "user", "content": filled_prompt}]

        if self.openai_client is None:
            # 本地 transformers 路径保持不变
            completion = llm_utils.generate_completion_transformers(
                messages, self.model, self.tokenizer, answer_prepend="Triplets: "
            )
        else:
            # DeepSeek OpenAI-compatible path.
            response = self.openai_client.chat.completions.create(
                model=self.openai_model_id,
                messages=messages,
                stream=False
            )
            completion =  (response.choices[0].message.content).strip()


        pairs = []
        for line in completion.splitlines():
            line = line.strip()
            if not line:
                continue

            # 先按第一个 ":" 切出 field 和剩余内容
            if ":" not in line:
                continue
            field, rest = line.split(":", 1)
            field = field.strip()
            rest = rest.strip()

            definition = rest
            example = None

            # 按 " | example:"（大小写不敏感）切分 definition 和 example
            # 允许 " | Example:" 等变体
            m = re.search(r"\s*\|\s*example\s*:\s*", rest, flags=re.IGNORECASE)
            if m:
                definition = rest[:m.start()].strip()
                example = rest[m.end():].strip()
                # 统一处理 example: NONE
                if example.upper() == "NONE":
                    example = None

            pairs.append([field, definition, example])

        return pairs


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
                # 简单退避，避免 429/503
                time.sleep(0.8 * (2 ** i))
        raise last_err


    
