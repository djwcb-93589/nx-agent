from typing import List
import edc.utils.llm_utils as llm_utils
from transformers import AutoModelForCausalLM, AutoTokenizer


class EntityExtractor:
    def __init__(self, model: AutoModelForCausalLM = None, tokenizer: AutoTokenizer = None, openai_model=None) -> None:
        assert openai_model is not None or (model is not None and tokenizer is not None)
        self.model = model
        self.tokenizer = tokenizer
        self.openai_model = openai_model

    def extract_entities(self, input_text_str: str, few_shot_examples_str: str, prompt_template_str: str):
        filled_prompt = prompt_template_str.format_map(
            {"few_shot_examples": few_shot_examples_str, "input_text": input_text_str}
        )
        messages = [{"role": "user", "content": filled_prompt}]

        if self.openai_model is None:
            # llm_utils.generate_completion_transformers([messages], self.model, self.tokenizer, device=self.device)
            completion = llm_utils.generate_completion_transformers(
                messages, self.model, self.tokenizer, answer_prepend="Entities: "
            )
        else:
            completion = llm_utils.openai_chat_completion(self.openai_model, None, messages)
        extracted_entities = llm_utils.parse_raw_entities(completion)
        return extracted_entities

    def merge_entities(
        self, input_text: str, entity_list_1: List[str], entity_list_2: List[str], prompt_template_str: str
    ):
        filled_prompt = prompt_template_str.format_map(
            {"input_text": input_text, "entity_list_1": entity_list_1, "entity_list_2": entity_list_2}
        )
        messages = [{"role": "user", "content": filled_prompt}]

        if self.openai_model is None:
            # llm_utils.generate_completion_transformers([messages], self.model, self.tokenizer, device=self.device)
            completion = llm_utils.generate_completion_transformers(
                messages, self.model, self.tokenizer, answer_prepend="Answer: "
            )
        else:
            completion = llm_utils.openai_chat_completion(self.openai_model, None, messages)
        extracted_entities = llm_utils.parse_raw_entities(completion)
        return extracted_entities
