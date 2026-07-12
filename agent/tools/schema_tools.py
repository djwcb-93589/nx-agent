from pathlib import Path
import csv
import json
import re
import shutil

from agent.tools import llm_tools, sampling_tools


RELATION_COLUMNS = [
    "subject_type",
    "subject_id_source",
    "predicate",
    "object_type",
    "object_id_source",
    "edge_properties",
    "condition",
]


def resolve_schemas_dir(schemas_dir, repo_root):
    path = Path(schemas_dir)
    if not path.is_absolute():
        path = Path(repo_root) / path
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_schema_for_source(
    source_name,
    logs,
    pipeline,
    schemas_dir,
    out_path,
    sample_size=8,
):
    schemas_dir = Path(schemas_dir)
    out_path = Path(out_path)
    schema_type = infer_schema_type(source_name, schemas_dir)
    existing = load_schema_bundle(schemas_dir, schema_type)
    generated = False

    if existing is None:
        generated_bundle = generate_schema_bundle(
            source_name=source_name,
            logs=logs,
            pipeline=pipeline,
            schemas_dir=schemas_dir,
            schema_type=schema_type,
            sample_size=sample_size,
        )
        save_schema_bundle(schemas_dir, generated_bundle)
        bundle = generated_bundle
        generated = True
    else:
        bundle = existing

    write_schema_outputs(out_path, bundle, generated=generated, source_name=source_name)
    return {
        "schema_type": bundle["schema_type"],
        "generated": generated,
        "poi_count": len(bundle["poi_fields"]),
        "relation_count": len(bundle["relations"]),
        "poi_file": str(out_path / "poi_schema.csv"),
        "relation_file": str(out_path / "relation_schema.csv"),
        "meta_file": str(out_path / "schema_meta.json"),
    }


def infer_schema_type(source_name, schemas_dir):
    source_lower = source_name.lower()
    candidates = {
        "apache": ["apache", "httpd", "access.log", "error.log"],
        "audit": ["audit"],
        "auth": ["auth.log", "/auth", "\\auth", "sshd", "sudo"],
        "dns": ["dnsmasq", "dns"],
        "firewall": ["firewallexample", "firewallexamplae", "firewall", "防火墙"],
        "syslog": ["syslog", "messages", "kern.log"],
    }
    for schema_type, markers in candidates.items():
        if any(marker in source_lower for marker in markers):
            return schema_type

    available = {
        path.name[: -len("_POI.csv")].lower()
        for path in Path(schemas_dir).glob("*_POI.csv")
    }
    stem = Path(source_name).stem.lower()
    normalized_stem = normalize_schema_name(stem)
    if normalized_stem in available:
        return normalized_stem
    return normalized_stem


def normalize_schema_name(name):
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_").lower()
    return normalized or "generated_log"


def load_schema_bundle(schemas_dir, schema_type):
    poi_path = Path(schemas_dir) / f"{schema_type}_POI.csv"
    relation_path = Path(schemas_dir) / f"{schema_type}_relation.csv"
    if not poi_path.is_file() or not relation_path.is_file():
        return None
    return {
        "schema_type": schema_type,
        "poi_fields": read_poi_csv(poi_path),
        "relations": read_relation_csv(relation_path),
        "alignment_notes": "Loaded from existing schema files.",
    }


def read_poi_csv(path):
    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)
        for row in reader:
            if not row:
                continue
            field = row[0].strip()
            if not field:
                continue
            rows.append(
                {
                    "field": normalize_field_name(field),
                    "description": row[1].strip() if len(row) > 1 else "",
                }
            )
    return rows


def read_relation_csv(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        rows = []
        for row in reader:
            rows.append({column: (row.get(column) or "").strip() for column in RELATION_COLUMNS})
    return rows


def generate_schema_bundle(
    source_name,
    logs,
    pipeline,
    schemas_dir,
    schema_type,
    sample_size=8,
):
    existing_catalog = load_existing_catalog(schemas_dir)
    global_fields = read_global_fields(schemas_dir)
    representative_logs = sampling_tools.select_representative_logs(
        logs=logs,
        sample_size=min(sample_size, max(1, len(logs))),
        metric="jaccard",
        max_logs=200,
    )
    messages = [
        {
            "role": "system",
            "content": (
                "You are a POI/relation schema designer for security log knowledge graphs. "
                "POI means only fields that are useful for constructing a knowledge graph, "
                "not every parsed variable. Align same-meaning fields strictly to existing "
                "canonical field names. Return valid JSON only."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "task": "Generate POI and relation schema for a log source without an existing schema.",
                    "source": source_name,
                    "proposed_schema_type": schema_type,
                    "representative_logs": representative_logs,
                    "global_canonical_fields": global_fields,
                    "existing_schema_catalog": existing_catalog,
                    "required_json_schema": {
                        "schema_type": "snake_case_log_type",
                        "poi_fields": [
                            {
                                "field": "canonical_snake_case_field",
                                "description": "why this field is KG-relevant",
                            }
                        ],
                        "relations": [
                            {
                                "subject_type": "EntityType",
                                "subject_id_source": "poi_field_name",
                                "predicate": "UPPER_SNAKE_CASE",
                                "object_type": "EntityType",
                                "object_id_source": "poi_field_name",
                                "edge_properties": "comma,separated,poi,fields",
                                "condition": "field not null AND ...",
                            }
                        ],
                        "alignment_notes": "short audit note explaining field alignment choices",
                    },
                    "constraints": [
                        "Use existing canonical field names whenever semantics match.",
                        "Do not include low-value parse-only variables as POI.",
                        "Relations must reference POI fields in id sources and edge_properties.",
                        "Prefer stable entity identifiers such as user, host, program, pid, src_ip, dst_ip, object_name, command, event_type, outcome.",
                    ],
                },
                ensure_ascii=False,
            ),
        },
    ]
    payload = llm_tools.generate_json(
        pipeline, messages=messages, max_tokens=4096, temperature=0.0
    )
    return validate_schema_payload(payload, fallback_schema_type=schema_type)


def load_existing_catalog(schemas_dir):
    catalog = {}
    for poi_path in sorted(Path(schemas_dir).glob("*_POI.csv")):
        schema_type = poi_path.name[: -len("_POI.csv")]
        relation_path = Path(schemas_dir) / f"{schema_type}_relation.csv"
        if not relation_path.is_file():
            continue
        poi_fields = read_poi_csv(poi_path)
        relations = read_relation_csv(relation_path)
        catalog[schema_type] = {
            "poi_fields": poi_fields,
            "relation_predicates": sorted(
                {row["predicate"] for row in relations if row.get("predicate")}
            ),
        }
    return catalog


def read_global_fields(schemas_dir):
    path = Path(schemas_dir) / "log_schema.csv"
    if not path.is_file():
        return []
    return read_poi_csv(path)


def validate_schema_payload(payload, fallback_schema_type):
    schema_type = normalize_schema_name(str(payload.get("schema_type") or fallback_schema_type))
    poi_fields = []
    seen_fields = set()
    for item in payload.get("poi_fields") or []:
        if not isinstance(item, dict):
            continue
        field = normalize_field_name(str(item.get("field") or ""))
        if not field or field in seen_fields:
            continue
        seen_fields.add(field)
        poi_fields.append(
            {
                "field": field,
                "description": str(item.get("description") or "").strip(),
            }
        )

    if not poi_fields:
        poi_fields = [
            {"field": "host", "description": "Hostname/device that emitted the log."},
            {"field": "program", "description": "Emitting application or service."},
            {
                "field": "event_type",
                "description": "Canonical event category inferred from the template.",
            },
            {"field": "outcome", "description": "Normalized event outcome."},
        ]

    poi_field_names = {item["field"] for item in poi_fields}
    relations = []
    for item in payload.get("relations") or []:
        if not isinstance(item, dict):
            continue
        row = {column: str(item.get(column) or "").strip() for column in RELATION_COLUMNS}
        row["subject_id_source"] = normalize_field_name(row["subject_id_source"])
        row["object_id_source"] = normalize_field_name(row["object_id_source"])
        row["edge_properties"] = normalize_edge_properties(row["edge_properties"], poi_field_names)
        if not row["predicate"]:
            continue
        if row["subject_id_source"] not in poi_field_names:
            continue
        if row["object_id_source"] not in poi_field_names:
            continue
        relations.append(row)

    return {
        "schema_type": schema_type,
        "poi_fields": poi_fields,
        "relations": relations,
        "alignment_notes": str(payload.get("alignment_notes") or "").strip(),
    }


def normalize_field_name(field):
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", field.strip()).strip("_").lower()
    return normalized


def normalize_edge_properties(edge_properties, poi_field_names):
    fields = []
    for raw_field in edge_properties.split(","):
        field = normalize_field_name(raw_field)
        if field and field in poi_field_names and field not in fields:
            fields.append(field)
    return ",".join(fields)


def save_schema_bundle(schemas_dir, bundle):
    schema_type = bundle["schema_type"]
    write_poi_csv(Path(schemas_dir) / f"{schema_type}_POI.csv", bundle["poi_fields"])
    write_relation_csv(
        Path(schemas_dir) / f"{schema_type}_relation.csv", bundle["relations"]
    )


def write_schema_outputs(out_path, bundle, generated, source_name):
    out_path.mkdir(parents=True, exist_ok=True)
    write_poi_csv(out_path / "poi_schema.csv", bundle["poi_fields"])
    write_relation_csv(out_path / "relation_schema.csv", bundle["relations"])
    with open(out_path / "schema_meta.json", "w", encoding="utf-8") as file:
        json.dump(
            {
                "source": source_name,
                "schema_type": bundle["schema_type"],
                "generated": generated,
                "poi_count": len(bundle["poi_fields"]),
                "relation_count": len(bundle["relations"]),
                "alignment_notes": bundle.get("alignment_notes", ""),
            },
            file,
            indent=2,
            ensure_ascii=False,
        )


def write_poi_csv(path, poi_fields):
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        for item in poi_fields:
            writer.writerow([item["field"], item.get("description", "")])


def write_relation_csv(path, relations):
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=RELATION_COLUMNS)
        writer.writeheader()
        for row in relations:
            writer.writerow({column: row.get(column, "") for column in RELATION_COLUMNS})


def copy_existing_schema_files(schemas_dir, schema_type, out_path):
    poi_path = Path(schemas_dir) / f"{schema_type}_POI.csv"
    relation_path = Path(schemas_dir) / f"{schema_type}_relation.csv"
    if poi_path.is_file():
        shutil.copyfile(poi_path, Path(out_path) / "poi_schema.csv")
    if relation_path.is_file():
        shutil.copyfile(relation_path, Path(out_path) / "relation_schema.csv")
