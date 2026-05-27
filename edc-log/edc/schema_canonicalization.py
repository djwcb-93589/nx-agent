from typing import List
import os
from pathlib import Path
import edc.utils.llm_utils as llm_utils
import re
from edc.utils.e5_mistral_utils import MistralForSequenceEmbedding
from transformers import AutoModelForCausalLM, AutoTokenizer
import numpy as np
import copy
from tqdm import tqdm
from sentence_transformers import SentenceTransformer
import logging
import time
from openai import OpenAI

logger = logging.getLogger(__name__)


class SchemaCanonicalizer:
    # The class to handle the last stage: Schema Canonicalization
    def __init__(
        self,
        target_schema_dict: dict,
        embedder,
        verify_model: AutoModelForCausalLM = None,
        verify_tokenizer: AutoTokenizer = None,
        verify_openai_client: OpenAI = None,
        verify_openai_model_id: str = None,
    ) -> None:
        # 现在支持：本地 LLM 或 HF Router API LLM（二选一）
        assert (verify_openai_client is not None and verify_openai_model_id is not None) or (
            verify_model is not None and verify_tokenizer is not None
        )
        self.verifier_model = verify_model
        self.verifier_tokenizer = verify_tokenizer
        self.verifier_openai_client = verify_openai_client
        self.verifier_openai_model_id = verify_openai_model_id

        self.schema_dict = target_schema_dict
        self.embedder = embedder

        # Embed target schema
        '''
        self.schema_embedding_dict = {}
        print("Embedding target schema...")
        for relation, relation_definition in tqdm(target_schema_dict.items()):
            embedding = self.embedder.encode(relation_definition)
            self.schema_embedding_dict[relation] = embedding        
        '''

    def retrieve_similar_relations(self, query_relation_definition: str, top_k=5):
        target_relation_list = list(self.schema_embedding_dict.keys())
        target_relation_embedding_list = list(self.schema_embedding_dict.values())
        if "sts_query" in self.embedder.prompts:
            query_embedding = self.embedder.encode(query_relation_definition, prompt_name="sts_query")
        else:
            query_embedding = self.embedder.encode(query_relation_definition)

        scores = np.array([query_embedding]) @ np.array(target_relation_embedding_list).T

        scores = scores[0]
        highest_score_indices = np.argsort(-scores)

        return {
            target_relation_list[idx]: self.schema_dict[target_relation_list[idx]]
            for idx in highest_score_indices[:top_k]
        }, [scores[idx] for idx in highest_score_indices[:top_k]]

    def llm_verify(
        self,
        input_text_str: str,
        query_triplet: List[str],
        query_relation_definition: str,
        prompt_template_str: str,
        candidate_relation_definition_dict: dict,
        relation_example_dict: dict = None,
    ):
        canonicalized_triplet = copy.deepcopy(query_triplet)
        choice_letters_list = []
        choices = ""

        candidate_relations = list(candidate_relation_definition_dict.keys())
        candidate_relation_descriptions = list(candidate_relation_definition_dict.values())

        for idx, rel in enumerate(candidate_relations):
            choice_letter = chr(ord("@") + idx + 1)
            choice_letters_list.append(choice_letter)
            choices += f"{choice_letter}. '{rel}': {candidate_relation_descriptions[idx]}\n"

            if relation_example_dict is not None:
                # 你这段原代码有索引 bug（candidate_relations[idx]['sentence']），先不动结构，建议你后面修
                ex = relation_example_dict.get(rel, {})
                if ex:
                    choices += f"Example: '{ex.get('triple','')}' can be extracted from '{ex.get('sentence','')}'\n"

        choices += f"{chr(ord('@') + len(candidate_relations) + 1)}. None of the above.\n"

        verification_prompt = prompt_template_str.format_map(
            {
                "input_text": input_text_str,
                "query_triplet": query_triplet,
                "query_relation": query_triplet[1],
                "query_relation_definition": query_relation_definition,
                "choices": choices,
            }
        )

        messages = [{"role": "user", "content": verification_prompt}]

        if self.verifier_openai_client is None:
            verification_result = llm_utils.generate_completion_transformers(
                messages, self.verifier_model, self.verifier_tokenizer,
                answer_prepend="Answer: ", max_new_token=5
            )
            # 这里原实现里 verification_result[0] 可能是字符串，保持你原逻辑
        else:
            verification_result = self._hf_router_chat_choice(messages)

        # verification_result 取首字符做选项
        ch = verification_result.strip()[:1] if isinstance(verification_result, str) else str(verification_result)[0]

        if ch in choice_letters_list:
            canonicalized_triplet = candidate_relations[choice_letters_list.index(ch)]
        else:
            return None

        return canonicalized_triplet


    def llm_verify_field_map(
        self,
        input_text_str: str,
        open_relation_definition_dict: dict,            # source fields -> definitions
        prompt_template_str: str,                       # the new prompt file content
        candidate_relation_definition_dict: dict,        # canonical fields -> definitions (9 fields)
    ):
        # 1) build canonical fields text (include NONE)
        canonical_lines = []
        for k, v in candidate_relation_definition_dict.items():
            canonical_lines.append(f"- {k}: {v}")
        canonical_lines.append("- NONE: No suitable canonical mapping for strict alignment.")
        canonical_fields_txt = "\n".join(canonical_lines)

        # 2) build source fields text
        # keep the extracted field names stable, do not rename here
        source_fields = list(open_relation_definition_dict.keys())
        source_lines = [f"- {k}: {open_relation_definition_dict[k]}" for k in source_fields]
        source_fields_txt = "\n".join(source_lines)

        # 3) build prompt
        verification_prompt = prompt_template_str.format_map(
            {
                "input_text": input_text_str,
                "source_fields": source_fields_txt,
                "canonical_fields": canonical_fields_txt,
            }
        )

        messages = [{"role": "user", "content": verification_prompt}]
        completion = self._hf_router_chat_choice(messages)


        # 5) parse mapping lines
        mapping = parse_field_mapping(completion, source_fields)

        return mapping


    def canonicalize(
        self,
        input_text_str: str,
        open_triplet,
        open_relation_definition_dict: dict,
        verify_prompt_template: str,
        enrich=False,
    ):
        self.schema_embedding_dict = {}
        print("Embedding target schema...")
        for relation, relation_definition in tqdm(self.schema_dict.items()):
            embedding = self.embedder.encode(relation_definition)
            self.schema_embedding_dict[relation] = embedding       
        if open_triplet in self.schema_dict:
            # The relation is already canonical
            # candidate_relations, candidate_scores = self.retrieve_similar_relations(
            #     open_relation_definition_dict[open_relation]
            # )
            return open_triplet, {}

        candidate_relations = []
        candidate_scores = []

        if len(self.schema_dict) != 0:

            candidate_relations, candidate_scores = self.retrieve_similar_relations(
                open_relation_definition_dict[open_triplet[1]]
            )            

            canonicalized_triplet = self.llm_verify(
                input_text_str,
                open_triplet,
                open_relation_definition_dict[open_triplet],
                verify_prompt_template,
                candidate_relations,
                None,
            )
        else:
            canonicalized_triplet = None

        if canonicalized_triplet is None:
            # Cannot be canonicalized
            if enrich:
                self.schema_dict[open_triplet] = open_relation_definition_dict[open_triplet]
                if "sts_query" in self.embedder.prompts:
                    embedding = self.embedder.encode(
                        open_relation_definition_dict[open_triplet], prompt_name="sts_query"
                    )
                else:
                    embedding = self.embedder.encode(open_relation_definition_dict[open_triplet])
                self.schema_embedding_dict[open_triplet] = embedding
                canonicalized_triplet = open_triplet
        return canonicalized_triplet, dict(zip(candidate_relations, candidate_scores))

    def canonicalize1(
        self,
        input_text_str: str,
        open_relation_definition_dict: dict,
        verify_prompt_template: str,
        enrich=False,
    ):
        self.schema_embedding_dict = {}


        candidate_relations = self.schema_dict

        if len(self.schema_dict) != 0:
            canonicalized_triplet = self.llm_verify_field_map(
                input_text_str,
                open_relation_definition_dict,
                verify_prompt_template,
                candidate_relations,
            )
        else:
            canonicalized_triplet = None

        if canonicalized_triplet is None:
            # Cannot be canonicalized
            if enrich:
                print(1)

        return canonicalized_triplet, candidate_relations

    def _hf_router_chat_choice(self, messages, retry=3) -> str:
        last_err = None
        for i in range(retry):
            try:
                resp = self.verifier_openai_client.chat.completions.create(
                    model="deepseek-chat",          # 或 self.verifier_openai_model_id
                    messages=messages,
                    temperature=0.0,
                    max_tokens=512,                   # 建议 >1，避免模型输出 "Answer: A" 被截断成 "A"/"Answer"
                )
                return (resp.choices[0].message.content or "").strip()
            except Exception as e:
                last_err = e
                time.sleep(0.8 * (2 ** i))
        raise last_err
    

def parse_field_mapping(completion: str, source_fields: list[str]) -> dict:
    """
    Parse lines like: field -> canonical
    Returns dict[field] = canonical or None
    """
    CANON_SET = {"host","log_source","event_type","status","actor","target","program","pid","object","NONE"}
    mapping = {f: None for f in source_fields}
    for line in completion.splitlines():
        line = line.strip()
        if not line or "->" not in line:
            continue
        left, right = line.split("->", 1)
        src = left.strip()
        dst = right.strip().strip(" .,'\"").upper() if right else "NONE"
        # normalize dst to canonical
        dst_norm = dst.lower()
        if dst in {"NONE"}:
            dst_norm = "NONE"
        # allow small variants (optional)
        # e.g. "LOG_SOURCE" "log_source"
        if dst_norm not in CANON_SET and dst_norm.upper() == "NONE":
            dst_norm = "NONE"
        if src in mapping:
            mapping[src] = None if dst_norm == "NONE" else dst_norm
    return mapping