from argparse import ArgumentParser
import json
import logging
import os
from pathlib import Path
import re

import pandas as pd

from event_template_bank import EventTemplateBank

AIT_ROOT = Path("./AIT")
TEMPLATE_SAMPLE_SIZE = 3
TEMPLATE_SAMPLE_SEED = 42
#SELECTED_AIT_CSV_FOR_EDC = None  # e.g. "./AIT/intranet_server/logs/auth/3.csv"
#SELECTED_AIT_CSV_FOR_EDC = "./AIT/intranet_server/logs/auth/3.csv"  # e.g. "./AIT/intranet_server/logs/auth/3.csv"
#SELECTED_AIT_CSV_FOR_EDC = "./AIT/inet-firewall/logs-label/dnsmasq/3.csv"
#SELECTED_AIT_CSV_FOR_EDC = "./AIT/internal_share/logs/audit_internal_share/audit_internal_share/3.csv"
#SELECTED_AIT_CSV_FOR_EDC = "./AIT/intranet_server/logs/apache2/intranet.price.fox.org-access/3.csv"
#SELECTED_AIT_CSV_FOR_EDC = "./AIT/intranet_server/logs/apache2/intranet.price.fox.org-error/3.csv"
#SELECTED_AIT_CSV_FOR_EDC = "./AIT/intranet_server/logs/audit_internal_server/audit_internal_server/3.csv"
SELECTED_AIT_CSV_FOR_EDC = "./AIT/vpn/logs/openvpn/3.csv"

def _infer_ait_log_kind(csv_path: Path, df: pd.DataFrame) -> str:
    normalized_path = str(csv_path).lower().replace("\\", "/")

    if "dnsmasq" in normalized_path:
        return "dns"

    if "/auth/" in normalized_path:
        return "auth"

    if "audit" in normalized_path:
        return "audit"

    if "Content" not in df.columns:
        return "generic"

    sample = df["Content"].dropna().astype(str)
    if not sample.empty and sample.str.startswith("type=").all():
        return "audit"

    return "generic"


def _normalize_audit_line(line: str) -> str:
    text = str(line).strip()
    match = re.match(r"^(type=[^ ]+)\s+(.*)$", text)
    if not match:
        return text

    log_type, remainder = match.groups()
    remainder = re.sub(r"^msg=audit:\s*", "", remainder.strip())
    return f"{log_type}: {remainder}" if remainder else log_type


def _normalize_prefixed_template(template: str, sample: str) -> str:
    sample_prefix, sample_sep, _ = str(sample).partition(": ")
    _, template_sep, template_suffix = str(template).partition(": ")
    if not sample_sep or not template_sep:
        return str(template)

    normalized_prefix = re.sub(r"\[[^\]]*\]", "[<*>]", sample_prefix)
    return f"{normalized_prefix}: {template_suffix}"


def _build_template2samples_from_ait_df(
    df: pd.DataFrame,
    csv_path: Path,
    k: int = TEMPLATE_SAMPLE_SIZE,
    seed: int = TEMPLATE_SAMPLE_SEED,
):
    required_columns = {"Content", "EventId", "RegexTemplate"}
    if not required_columns.issubset(df.columns):
        return None

    work = df[["RegexTemplate", "Content", "EventId"]].rename(
        columns={
            "RegexTemplate": "eventTemplate",
            "Content": "content",
            "EventId": "eventId",
        }
    ).copy()

    work["eventTemplate"] = work["eventTemplate"].astype("string").fillna("").str.strip()
    work["content"] = work["content"].astype("string").fillna("").str.strip()
    work["eventId"] = work["eventId"].astype("string").fillna("").str.strip()
    work = work[(work["eventTemplate"] != "") & (work["content"] != "")]

    if work.empty:
        return None

    log_kind = _infer_ait_log_kind(csv_path, df)

    if log_kind == "audit":
        work["eventTemplate"] = work["eventTemplate"].map(_normalize_audit_line)
        work["content"] = work["content"].map(_normalize_audit_line)

    work = work.drop_duplicates(subset=["eventTemplate", "content"])

    blocks = []
    ids = []

    for template, group in work.groupby("eventTemplate", sort=True):
        template = str(template)
        if log_kind in {"auth", "dns"}:
            template = _normalize_prefixed_template(template, group["content"].iloc[0])

        sample_source = group["content"].drop_duplicates()
        sample_count = min(k, len(sample_source))
        random_state = None if seed is None else EventTemplateBank._stable_seed(str(template), seed)
        samples = sample_source.sample(n=sample_count, random_state=random_state).tolist()

        first_event_id = ""
        for value in group["eventId"].tolist():
            value = str(value).strip()
            if value and value.lower() != "nan":
                first_event_id = value
                break

        blocks.append("Template: " + str(template) + "\nSamples:\n- " + "\n- ".join(samples))
        ids.append(first_event_id)

    return [blocks, ids]


def _load_existing_template2samples(json_path: Path):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    if (
        not isinstance(data, list)
        or len(data) != 2
        or not isinstance(data[0], list)
        or not isinstance(data[1], list)
    ):
        return None

    return data


def generate_template2samples_jsons_from_ait(
    ait_root: Path = AIT_ROOT,
    k: int = TEMPLATE_SAMPLE_SIZE,
    seed: int = TEMPLATE_SAMPLE_SEED,
):
    generated = {}

    for csv_path in sorted(ait_root.rglob("*.csv")):
        json_path = csv_path.with_name("template2samples.json")

        if json_path.exists():
            template2samples = _load_existing_template2samples(json_path)
            if template2samples is not None:
                generated[csv_path.resolve()] = template2samples
                print(f"Loaded JSON: {json_path}")
                continue

            print(f"Invalid JSON cache, regenerate from CSV: {json_path}")

        try:
            df = pd.read_csv(csv_path)
        except Exception as exc:
            print(f"Skip file: {csv_path} (read failed: {exc})")
            continue

        template2samples = _build_template2samples_from_ait_df(df, csv_path, k=k, seed=seed)
        if template2samples is None:
            print(f"Skip file: {csv_path} (missing Content/EventId/RegexTemplate or no valid rows)")
            continue

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(template2samples, f, ensure_ascii=False, indent=4)

        generated[csv_path.resolve()] = template2samples
        print(f"Saved JSON: {json_path}")

    return generated


def _build_ait_output_tag(csv_path: Path) -> str:
    relative_path = csv_path.resolve().relative_to(AIT_ROOT.resolve()).with_suffix("")
    parts = [re.sub(r"[^0-9A-Za-z]+", "_", part).strip("_") for part in relative_path.parts]
    tag = "_".join(part for part in parts if part)
    return tag or "ait"


os.environ["TOKENIZERS_PARALLELISM"] = "false"


if __name__ == "__main__":
    generated_template2samples = generate_template2samples_jsons_from_ait()

    if not generated_template2samples:
        raise SystemExit("No eligible CSV files found under AIT.")

    if not SELECTED_AIT_CSV_FOR_EDC:
        print("Finished generating template2samples.json for all eligible AIT CSV files.")
        #raise SystemExit(0)

    selected_csv_path = Path(SELECTED_AIT_CSV_FOR_EDC).resolve()
    template2samples = generated_template2samples.get(selected_csv_path)
    if template2samples is None:
        raise SystemExit(f"Selected AIT CSV not found for EDC: {selected_csv_path}")

    type = _build_ait_output_tag(selected_csv_path)

    from edc.edc_framework import EDC

    parser = ArgumentParser()
    # OIE module setting
    parser.add_argument(
        "--oie_llm", default="deepseek-chat", help="LLM used for open information extraction."
    )
    parser.add_argument(
        "--oie_prompt_template_file_path",
        default="./prompt_templates/oie_template.txt",
        help="Promp template used for open information extraction.",
    )
    parser.add_argument(
        "--oie_few_shot_example_file_path",
        default="./few_shot_examples/example/oie_few_shot_examples.txt",
        help="Few shot examples used for open information extraction.",
    )

    # Schema Definition setting
    parser.add_argument(
        "--sd_llm", default="deepseek-chat", help="LLM used for schema definition."
    )
    parser.add_argument(
        "--sd_prompt_template_file_path",
        default="./prompt_templates/sd_template.txt",
        help="Prompt template used for schema definition.",
    )
    parser.add_argument(
        "--sd_few_shot_example_file_path",
        default="./few_shot_examples/example/sd_few_shot_examples.txt",
        help="Few shot examples used for schema definition.",
    )

    # Schema Canonicalization setting
    parser.add_argument(
        "--sc_llm",
        default="deepseek-chat",
        help="LLM used for schema canonicaliztion verification.",
    )
    parser.add_argument(
        "--sc_prompt_template_file_path",
        default="./prompt_templates/sc_template_deepseek_mapping.txt",
        help="Prompt template used for schema canonicalization verification.",
    )

    parser.add_argument(
        "--oie_refine_prompt_template_file_path",
        default="./prompt_templates/oie_r_template.txt",
        help="Prompt template used for refined open information extraction.",
    )
    parser.add_argument(
        "--oie_refine_few_shot_example_file_path",
        default="./few_shot_examples/example/oie_few_shot_refine_examples.txt",
        help="Few shot examples used for refined open information extraction.",
    )
    parser.add_argument("--ee_llm", default="deepseek-chat", help="LLM used for entity extraction.")
    parser.add_argument(
        "--ee_prompt_template_file_path",
        default="./prompt_templates/ee_template.txt",
        help="Prompt templated used for entity extraction.",
    )
    parser.add_argument(
        "--ee_few_shot_example_file_path",
        default="./few_shot_examples/example/ee_few_shot_examples.txt",
        help="Few shot examples used for entity extraction.",
    )
    parser.add_argument(
        "--em_prompt_template_file_path",
        default="./prompt_templates/em_template.txt",
        help="Prompt template used for entity merging.",
    )

    # Input setting
    parser.add_argument(
        "--input_text_file_path",
        default="./datasets/example 25.txt",
        help="File containing input texts to extract KG from, each line contains one piece of text.",
    )
    parser.add_argument(
        "--target_schema_path",
        default="./schemas/vpn_POI v2.csv",
        help="File containing the target schema to align to.",
    )
    parser.add_argument("--refinement_iterations", default=0, type=int, help="Number of iteration to run.")
    parser.add_argument(
        "--enrich_schema",
        action="store_true",
        help="Whether un-canonicalizable relations should be added to the schema.",
    )

    # Output setting
    parser.add_argument("--output_dir", default="./log_output", help="Directory to output to.")
    parser.add_argument("--logging_verbose", action="store_const", dest="loglevel", const=logging.INFO)
    parser.add_argument("--logging_debug", action="store_const", dest="loglevel", const=logging.DEBUG)

    args = parser.parse_args()
    args = vars(args)

    edc = EDC(**args)

    input_text_list = template2samples[0]
    output_kg = edc.extract_kg(
        input_text_list,
        args["output_dir"],
        refinement_iterations=args["refinement_iterations"],
        oie=False,
        type=type,
    )
