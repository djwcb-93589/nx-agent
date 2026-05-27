'''
reload(logging)
'''
from typing import List, Dict, Any, Tuple
from edc.schema_definition import SchemaDefiner
from edc.schema_canonicalization import SchemaCanonicalizer
from edc.entity_extraction import EntityExtractor
import edc.utils.llm_utils as llm_utils
import numpy as np
from edc.utils.e5_mistral_utils import MistralForSequenceEmbedding
from edc.schema_retriever import SchemaRetriever
from sentence_transformers import SentenceTransformer
from transformers import AutoModelForCausalLM, AutoTokenizer
from edc.extract import Extractor
from openai import OpenAI
from functools import partial
from importlib import reload
import csv
import random
import json
import copy
from tqdm import tqdm
import pathlib
import os
from typing import List
import logging
from huggingface_hub import InferenceClient
from env_utils import get_env, load_dotenv

load_dotenv()
os.environ.setdefault("HF_TOKEN", get_env("HF_TOKEN"))
os.environ.setdefault("DS_TOKEN", get_env("DEEPSEEK_API_KEY", aliases=("DS_TOKEN", "OPENAI_API_KEY", "OPENAI_KEY")))

#os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7897'
#os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7897'

logger = logging.getLogger(__name__)

class HFEmbedder:
    """
    用 HF Inference Providers 做 embedding（E5）。
    encode(text) -> np.ndarray
    """
    def __init__(self, model_id: str, provider: str = "nebius", api_key: str = None,
                 prompt_name: str = None, normalize: bool = True):
        self.model_id = model_id
        self.client = InferenceClient(provider=provider, api_key=api_key or os.environ["HF_TOKEN"])
        self.prompt_name = prompt_name
        self.normalize = normalize

        # 为了兼容你原逻辑里用 self.embedder.prompts 判断
        self.prompts = {"sts_query": True} if prompt_name else {}

    def encode(self, text, prompt_name: str = None):
        # 兼容 SentenceTransformer 的 encode：支持 str 或 list[str]
        use_prompt = prompt_name or self.prompt_name

        vec = self.client.feature_extraction(
            text,
            model=self.model_id,
            prompt_name=use_prompt,
            normalize=self.normalize,
        )
        arr = np.asarray(vec, dtype=np.float32)

        if isinstance(text, str) and arr.ndim == 2 and arr.shape[0] == 1:
            arr = arr[0]

        return arr

class EDC:
    def __init__(self, **edc_configuration) -> None:
        # OIE module settings 开放抽取模块
        self.oie_llm_name = edc_configuration["oie_llm"]
        self.oie_prompt_template_file_path = edc_configuration["oie_prompt_template_file_path"]
        self.oie_few_shot_example_file_path = edc_configuration["oie_few_shot_example_file_path"] #少样本提示

        # Schema Definition module settings Schema Definition 是 EDC 框架的第二阶段核心模块，其核心功能是为开放信息抽取（OIE）阶段提取的三元组所诱导的 schema 组件（如关系类型）生成语义明确的自然语言定义，为后续的规范化阶段提供关键的语义依据
        # 模块通过 self.sd_template_file_path 加载提示词模板，通过 self.sd_few_shot_example_file_path 读取少样本示例（如文本、三元组与对应关系定义的配对样例），以引导 LLM 生成符合格式和精度要求的定义
        self.sd_llm_name = edc_configuration["sd_llm"] #Schema定义模块
        self.sd_template_file_path = edc_configuration["sd_prompt_template_file_path"]
        self.sd_few_shot_example_file_path = edc_configuration["sd_few_shot_example_file_path"]

        # Schema Canonicalization module settings Schema Canonicalization 是 EDC 框架的第三阶段核心模块，其功能是基于 Schema Definition 阶段生成的语义定义，对 OIE 阶段的三元组进行标准化处理，消除冗余和歧义，最终生成简洁、一致的知识图谱
        self.sc_llm_name = edc_configuration["sc_llm"]
        #通过 self.sc_embedder_name 配置的句子嵌入模型（如论文中的 E5-Mistral-7b），将 Schema Definition 阶段生成的组件定义转换为向量，再通过向量相似度搜索找到语义最接近的 schema 组件（预定义 schema 或自生成 schema 中的组件）
        self.sc_embedder_name = edc_configuration["sc_embedder"]
        #通过 self.sc_template_file_path 加载提示词模板，引导 LLM 完成组件匹配验证与三元组转换（如提供候选关系及定义，让 LLM 选择最优转换方案）
        self.sc_template_file_path = edc_configuration["sc_prompt_template_file_path"]

        # Refinement settings
        # 语义角色标注适配器路径 - 用于加载语义角色标注的适配模型
        self.sr_adapter_path = edc_configuration["sr_adapter_path"]
        # 语义角色嵌入模型名称 - 指定用于生成语义角色嵌入的模型
        self.sr_embedder_name = edc_configuration["sr_embedder"]
        # 开放信息抽取精修提示模板文件路径 - 存储开放信息抽取精修阶段使用的提示词模板
        self.oie_r_prompt_template_file_path = edc_configuration["oie_refine_prompt_template_file_path"]
        # 开放信息抽取精修少样本示例文件路径 - 存储用于开放信息抽取精修的少样本示例
        self.oie_r_few_shot_example_file_path = edc_configuration["oie_refine_few_shot_example_file_path"]

        # 实体提取大语言模型名称 - 指定用于实体提取的大语言模型
        self.ee_llm_name = edc_configuration["ee_llm"]
        # 实体提取提示模板文件路径 - 存储实体提取阶段使用的提示词模板
        self.ee_template_file_path = edc_configuration["ee_prompt_template_file_path"]
        # 实体提取少样本示例文件路径 - 存储用于实体提取的少样本示例
        self.ee_few_shot_example_file_path = edc_configuration["ee_few_shot_example_file_path"]

        # 实体匹配提示模板文件路径 - 存储实体匹配阶段使用的提示词模板
        self.em_template_file_path = edc_configuration["em_prompt_template_file_path"]

        # 初始 schema 路径 - 存储目标领域初始 schema（数据模式）的文件路径
        self.initial_schema_path = edc_configuration["target_schema_path"]
        # 是否扩展 schema - 布尔值，指示是否在处理过程中动态扩展初始 schema
        self.enrich_schema = edc_configuration["enrich_schema"]

        if self.initial_schema_path is not None:
            reader = csv.reader(open(self.initial_schema_path, "r"))
            self.schema = {}
            for row in reader:
                relation, relation_definition = row
                self.schema[relation] = relation_definition
        else:
            self.schema = {}

        # Load the needed models and tokenizers
        self.needed_model_set = set(
            [self.oie_llm_name, self.sd_llm_name, self.sc_llm_name, self.sc_embedder_name, self.ee_llm_name]
        )

        self.loaded_model_dict = {}

        logging.basicConfig(level=edc_configuration["loglevel"])

        logger.info(f"Model used: {self.needed_model_set}")

    def oie(
        self, input_text_list: List[str], previous_extracted_triplets_list: List[List[str]] = None, free_model=True, type = None
    ):
        # Load the HF model for OIE
        if free_model:
            client = self.load_model(self.oie_llm_name, "deepseek")
            extractor = Extractor(
                openai_client=client,
                openai_model_id=self.oie_llm_name,  # 注意：这里要包含 provider 后缀
                max_tokens=512,
                temperature=1.0,
            )


        oie_triples_list = []
        entity_hint_list = None
        relation_hint_list = None

        if previous_extracted_triplets_list is not None:
            # Refined OIE
            logger.info("Running Refined OIE...")
            oie_refinement_prompt_template_str = open(self.oie_r_prompt_template_file_path).read()
            oie_refinement_few_shot_examples_str = open(self.oie_r_few_shot_example_file_path).read()

            logger.info("Putting together the refinement hint...")
            entity_hint_list, relation_hint_list = self.construct_refinement_hint(
                input_text_list, previous_extracted_triplets_list, free_model=free_model
            )

            assert len(previous_extracted_triplets_list) == len(input_text_list)
            for idx, input_text in enumerate(tqdm(input_text_list)):
                input_text = input_text_list[idx]
                entity_hint_str = entity_hint_list[idx]
                relation_hint_str = relation_hint_list[idx]
                refined_oie_triplets = extractor.extract(
                    input_text,
                    oie_refinement_few_shot_examples_str,
                    oie_refinement_prompt_template_str,
                    entity_hint_str,
                    relation_hint_str,
                )
                oie_triples_list.append(refined_oie_triplets)
        else:
            # Normal OIE
            #entity_hint_list = ["" for _ in input_text_list]
            #relation_hint_list = ["" for _ in input_text_list]
            #logger.info("Running OIE...")
            #oie_few_shot_examples_str = open(self.oie_few_shot_example_file_path, "r", encoding="utf-8").read()
            oie_few_shot_prompt_template_str = open(self.oie_prompt_template_file_path, "r", encoding="utf-8").read()

            for input_text in tqdm(input_text_list):
                oie_triples = extractor.extract(input_text, oie_few_shot_prompt_template_str)
                oie_triples_list.append(oie_triples)
                logger.debug(f"{input_text}\n -> {oie_triples}\n")
            json_path = f"pairs_{type}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(oie_triples_list, f, ensure_ascii=False, indent=3)
            logger.info("OIE finished.")
        '''
        if free_model:
            logger.info(f"Freeing model {self.oie_llm_name} as it is no longer needed")
            llm_utils.free_model(oie_model, oie_tokenizer)
            del self.loaded_model_dict[self.oie_llm_name]
        '''

        return oie_triples_list, entity_hint_list, relation_hint_list

    def load_model(self, model_name, model_type):
        assert model_type in ["sts", "deepseek", "hf_api"]

        cache_key = f"{model_type}:{model_name}"
        if cache_key in self.loaded_model_dict:
            logger.info(f"Model {cache_key} is already loaded, reusing it.")
            return self.loaded_model_dict[cache_key]

        logger.info(f"Loading model {cache_key}")

        if model_type == "deepseek":
            ds_token = get_env("DS_TOKEN", aliases=("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENAI_KEY"))
            client = OpenAI(
                api_key=ds_token,
                base_url=get_env("DEEPSEEK_BASE_URL", "https://api.deepseek.com"))
            self.loaded_model_dict[cache_key] = client

        elif model_type == "hf_api":
            hf_token = os.environ.get("HF_TOKEN")
            if not hf_token:
                raise RuntimeError("HF_TOKEN is not set in environment variables.")

            client = OpenAI(
                base_url="https://router.huggingface.co/v1",
                api_key=hf_token,
            )
            self.loaded_model_dict[cache_key] = client

        elif model_type == "sts":
            model = SentenceTransformer(model_name, trust_remote_code=True)
            self.loaded_model_dict[cache_key] = model

        return self.loaded_model_dict[cache_key]

    def schema_definition(self, input_text_list: List[str], oie_triplets_list: List[List[str]], free_model=False):
        assert len(input_text_list) == len(oie_triplets_list)
        
        # === 走 HF Router API：load_model 返回 OpenAI client ===
        client = self.load_model(self.sd_llm_name, "hf_api")

        schema_definer = SchemaDefiner(
            openai_client=client,
            openai_model_id=self.sd_llm_name,   # 建议写成 "xxx:provider" 例如 "...:featherless-ai"
            max_tokens=512,
            temperature=0.0,
            retry=3,
        )

        schema_definition_few_shot_prompt_template_str = open(self.sd_template_file_path, "r", encoding="utf-8").read()
        schema_definition_few_shot_examples_str = open(self.sd_few_shot_example_file_path, "r", encoding="utf-8").read()
        schema_definition_dict_list = []

        logger.info("Running Schema Definition...")
        for idx, oie_triplets in enumerate(tqdm(oie_triplets_list)):
            schema_definition_dict = schema_definer.define_schema(
                input_text_list[idx],
                oie_triplets,
                schema_definition_few_shot_examples_str,
                schema_definition_few_shot_prompt_template_str,
            )
            schema_definition_dict_list.append(schema_definition_dict)
            logger.debug(f"{input_text_list[idx]}, {oie_triplets}\n -> {schema_definition_dict}\n")

        logger.info("Schema Definition finished.")
        '''
        if free_model:
            logger.info(f"Freeing model {self.sd_llm_name} as it is no longer needed")
            llm_utils.free_model(sd_model, sd_tokenizer)
            del self.loaded_model_dict[self.sd_llm_name]
        '''
        return schema_definition_dict_list

    def schema_canonicalization(
        self,
        input_text_list: List[str],
        oie_triplets_list: List[List[str]],
        free_model=False,
        embedding = False
    ):
        #assert len(input_text_list) == len(oie_triplets_list) == len(schema_definition_dict_list)
        logger.info("Running Schema Canonicalization...")

        sc_verify_prompt_template_str = open(self.sc_template_file_path, "r", encoding="utf-8").read()
        no_embedding_prompt_template_str = open(self.sc_template_file_path, "r", encoding="utf-8").read()

        # === 1) embedder 改成 API（E5）===
        sc_embedder = HFEmbedder(
            model_id=self.sc_embedder_name,      # 例如 "intfloat/e5-mistral-7b-instruct"
            provider="nebius",
            prompt_name="web_search_query",      # 可选：按你需求
            normalize=True,
        )

        # === 2) verifier 改成 HF Router chat API（Mistral）===
        sc_client = self.load_model(self.sc_llm_name, "deepseek")  # 返回 OpenAI client
        schema_canonicalizer = SchemaCanonicalizer(
            self.schema,
            sc_embedder,
            verify_openai_client=sc_client,
            verify_openai_model_id=self.sc_llm_name,  # 例如 "mistralai/Mistral-7B-Instruct-v0.2:featherless-ai"
        )

        canonicalized_triplets_list = []
        canon_candidate_dict_per_entry_list = []

        for idx, input_text in enumerate(tqdm(input_text_list)):
            field_definition_pairs = [
                (item[0], item[1])
                for item in oie_triplets_list[idx]
                if isinstance(item, list) and len(item) >= 2
            ]
            oie_triplets = [field for field, _ in field_definition_pairs]
            sd_dict = {field: definition for field, definition in field_definition_pairs}

            canonicalized_triplets = []
            canon_candidate_dict_list = []
            if embedding:
                for oie_triplet in enumerate(oie_triplets):
                    canonicalized_triplet, canon_candidate_dict = schema_canonicalizer.canonicalize(
                        input_text, oie_triplet, sd_dict, sc_verify_prompt_template_str, self.enrich_schema
                    )
                    canonicalized_triplets.append(canonicalized_triplet)
                    canon_candidate_dict_list.append(canon_candidate_dict) 
            else:
                canonicalized_triplets, canon_candidate_dict_list = schema_canonicalizer.canonicalize1(
                    input_text, sd_dict, no_embedding_prompt_template_str, self.enrich_schema
                )
            canonicalized_triplets_list.append(canonicalized_triplets)
            canon_candidate_dict_per_entry_list.append(canon_candidate_dict_list)

            print(f"{input_text}\n, {canonicalized_triplets}")
            #logger.debug(f"Retrieved candidate relations {canon_candidate_dict}")

        logger.info("Schema Canonicalization finished.")

        # === free_model：API 不需要释放 GPU，只可选删缓存引用 ===
        if free_model:
            logger.info(f"Freeing SC models as no longer needed (API mode: skip GPU free)")
            for k in (self.sc_llm_name, f"hf_api:{self.sc_llm_name}"):
                if k in self.loaded_model_dict:
                    del self.loaded_model_dict[k]

        return canonicalized_triplets_list, canon_candidate_dict_per_entry_list


    def construct_refinement_hint(
        self,
        input_text_list: List[str],
        extracted_triplets_list: List[List[List[str]]],
        include_relation_example="self",
        relation_top_k=10,
        free_model=False,
    ):
        entity_extraction_few_shot_examples_str = open(self.ee_few_shot_example_file_path).read()
        entity_extraction_prompt_template_str = open(self.ee_template_file_path).read()

        entity_merging_prompt_template_str = open(self.em_template_file_path).read()

        entity_hint_list = []
        relation_hint_list = []

        # Initialize entity extractor
        if not llm_utils.is_model_openai(self.ee_llm_name):
            # Load the HF model for Schema Definition
            ee_model, ee_tokenizer = self.load_model(self.ee_llm_name, "hf")
            # if self.ee_llm_name not in self.loaded_model_dict:
            #     logger.info(f"Loading model {self.ee_llm_name}")
            #     ee_model, ee_tokenizer = (
            #         AutoModelForCausalLM.from_pretrained(self.ee_llm_name, device_map="auto"),
            #         AutoTokenizer.from_pretrained(self.ee_llm_name),
            #     )
            #     self.loaded_model_dict[self.ee_llm_name] = (ee_model, ee_tokenizer)
            # else:
            #     logger.info(f"Model {self.ee_llm_name} is already loaded, reusing it.")
            #     ee_model, ee_tokenizer = self.loaded_model_dict[self.ee_llm_name]
            entity_extractor = EntityExtractor(model=ee_model, tokenizer=ee_tokenizer)
        else:
            entity_extractor = EntityExtractor(openai_model=self.sd_llm_name)

        # Initialize schema retriever
        # if self.sr_embedder_name not in self.loaded_model_dict:
        #     logger.info(f"Loading model {self.sr_embedder_name}.")
        #     sr_embedding_model = SentenceTransformer(self.sr_embedder_name)
        #     self.loaded_model_dict[self.sr_embedder_name] = sr_embedding_model
        # else:
        #     sr_embedding_model = self.loaded_model_dict[self.sr_embedder_name]
        #     logger.info(f"Model {self.sr_embedder_name} is already loaded, reusing it.")
        sr_embedding_model = self.load_model(self.sr_embedder_name, "sts")

        schema_retriever = SchemaRetriever(
            self.schema,
            sr_embedding_model,
            None,
            finetuned_e5mistral=False,
        )

        relation_example_dict = {}
        if include_relation_example == "self":
            # Include an example of where this relation can be extracted
            for idx in range(len(input_text_list)):
                input_text_str = input_text_list[idx]
                extracted_triplets = extracted_triplets_list[idx]
                for triplet in extracted_triplets:
                    relation = triplet[1]
                    if relation not in relation_example_dict:
                        relation_example_dict[relation] = [{"text": input_text_str, "triplet": triplet}]
                    else:
                        relation_example_dict[relation].append({"text": input_text_str, "triplet": triplet})
        else:
            # Todo: allow to pass gold examples of relations
            pass

        for idx in tqdm(range(len(input_text_list))):
            input_text_str = input_text_list[idx]
            extracted_triplets = extracted_triplets_list[idx]

            previous_relations = set()
            previous_entities = set()

            for triplet in extracted_triplets:
                previous_entities.add(triplet[0])
                previous_entities.add(triplet[2])
                previous_relations.add(triplet[1])

            previous_entities = list(previous_entities)
            previous_relations = list(previous_relations)

            # Obtain candidate entities
            extracted_entities = entity_extractor.extract_entities(
                input_text_str, entity_extraction_few_shot_examples_str, entity_extraction_prompt_template_str
            )
            merged_entities = entity_extractor.merge_entities(
                input_text_str, previous_entities, extracted_entities, entity_merging_prompt_template_str
            )
            entity_hint_list.append(str(merged_entities))

            # Obtain candidate relations
            hint_relations = previous_relations

            retrieved_relations = schema_retriever.retrieve_relevant_relations(input_text_str)

            counter = 0

            for relation in retrieved_relations:
                if counter >= relation_top_k:
                    break
                else:
                    if relation not in hint_relations:
                        hint_relations.append(relation)

            candidate_relation_str = ""
            for relation_idx, relation in enumerate(hint_relations):
                if relation not in self.schema:
                    continue

                relation_definition = self.schema[relation]

                candidate_relation_str += f"{relation_idx+1}. {relation}: {relation_definition}\n"
                if include_relation_example == "self":
                    if relation not in relation_example_dict:
                        # candidate_relation_str += "Example: None.\n"
                        pass
                    else:
                        selected_example = None
                        if len(relation_example_dict[relation]) != 0:
                            selected_example = random.choice(relation_example_dict[relation])
                        # for example in relation_example_dict[relation]:
                        #     if example["text"] != input_text_str:
                        #         selected_example = example
                        #         break
                        if selected_example is not None:
                            candidate_relation_str += f"""For example, {selected_example['triplet']} can be extracted from "{selected_example['text']}"\n"""
                        else:
                            # candidate_relation_str += "Example: None.\n"
                            pass
            relation_hint_list.append(candidate_relation_str)

        if free_model:
            logger.info(f"Freeing model {self.sr_embedder_name, self.ee_llm_name} as it is no longer needed")
            llm_utils.free_model(sr_embedding_model)
            llm_utils.free_model(ee_model, ee_tokenizer)
            del self.loaded_model_dict[self.sr_embedder_name]
            del self.loaded_model_dict[self.ee_llm_name]
        return entity_hint_list, relation_hint_list

    def extract_kg(self, input_text_list: List[str], output_dir: str = None, refinement_iterations=0, oie: bool = True, type: str = None):
        '''
        if output_dir is not None:
            if os.path.exists(output_dir):
                logger.error(f"Output directory {output_dir} already exists! Quitting.")
                exit()
            for iteration in range(refinement_iterations + 1):
                pathlib.Path(f"{output_dir}/iter{iteration}").mkdir(parents=True, exist_ok=True)        
        '''

        # EDC run
        logger.info("EDC starts running...")

        required_model_dict = {
            "oie": self.oie_llm_name,
            "sd": self.sd_llm_name,
            "sc_embed": self.sc_embedder_name,
            "sc_verify": self.sc_llm_name,
            "ee": self.ee_llm_name,
            "sr": self.sr_embedder_name,
        }

        triplets_from_last_iteration = None
        for iteration in range(refinement_iterations + 1):
            logger.info(f"Iteration {iteration}:")

            iteration_result_dir = f"{output_dir}/iter{iteration}"

            required_model_dict_current_iteration = copy.deepcopy(required_model_dict)

            if oie:
                del required_model_dict_current_iteration["oie"]
                oie_triplets_list = self.oie(
                    input_text_list,
                    #free_model=self.oie_llm_name not in required_model_dict_current_iteration.values()
                    #and iteration == refinement_iterations,
                    previous_extracted_triplets_list=triplets_from_last_iteration,
                    type = type
                )
                '''
                del required_model_dict_current_iteration["sd"]
                sd_dict_list = self.schema_definition(
                    input_text_list,
                    oie_triplets_list,
                    free_model=self.sd_llm_name not in required_model_dict_current_iteration.values()
                    and iteration == refinement_iterations,
                )
                '''
            else:
                json_path = f"pairs_{type}.json"
                with open(json_path, "r", encoding="utf-8") as f:
                    oie_triplets_list = json.load(f)
            del required_model_dict_current_iteration["sc_embed"]
            del required_model_dict_current_iteration["sc_verify"]
            canon_triplets_list, canon_candidate_dict_list = self.schema_canonicalization(
                input_text_list,
                oie_triplets_list,
                free_model=self.sc_llm_name not in required_model_dict_current_iteration.values()
                and iteration == refinement_iterations,
            )
            generalkey = list(canon_candidate_dict_list[0].keys())
            self.split_mappings_keep_other_keys(canon_triplets_list, generalkey, type)

        return canon_triplets_list
    def split_mappings_keep_other_keys(self,
                canon_triplets_list: List[Dict[str, Any]],
                generalkey: List[str],
                type,
            ) -> Tuple[List[List[str]], List[List[str]]]:
                general_set = set(generalkey)

                success_values_list: List[List[str]] = []  # 每条：['event_type','pid','program',...]
                other_keys_list: List[List[str]] = []      # 每条：['apparmor','operation','info',...]
                schema = []
                for m in canon_triplets_list:
                    # 1) 映射成功：只要 value（通用 schema 字段名）
                    #success_vals = [v for v in m.values() if v in general_set]
                    success_vals = {k: v for k, v in m.items() if v in general_set}
                    # 2) 保留 general 之外的“原始 key”
                    other_keys = [k for k, v in m.items() if v not in general_set]

                    success_values_list.append(success_vals)
                    other_keys_list.append(other_keys)
                    schema.append([success_vals, other_keys])
                save_path = f"schema_{type}.json"
                # 1. 保存多层列表到JSON文件
                with open(save_path, "w", encoding="utf-8") as f:
                    # ensure_ascii=False：支持中文（如果列表中有中文）；indent=4：格式化输出，增强可读性
                    json.dump(schema, f, ensure_ascii=False, indent=4)
