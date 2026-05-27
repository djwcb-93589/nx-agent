# log_kg_builder

Rule-driven, reusable CSV-to-Neo4j pipeline for deterministic log KG construction.

The pipeline is generic for `audit / auth / dns / apache / vpn` as long as you provide:

1. relation rules CSV: `subject_type, subject_id_source, predicate, object_type, object_id_source, edge_properties, condition`
2. params extracted CSV: one row per log event, columns are canonical fields

## Project layout

```text
log_kg_builder/
  main.py
  requirements.txt
  configs/
    dns_example.json
    auth_example.json
    audit_example.json
  kg/
    conditions.py
    config.py
    graph_builder.py
    id_strategy.py
    neo4j_writer.py
    normalization.py
    rules.py
```

## Core modules

- `rules.py`: load/validate `xxx_relation.csv`
- `conditions.py`: parse `condition` expressions
- `id_strategy.py`: unified node ID generation and node properties
- `graph_builder.py`: apply rules row-by-row, build/deduplicate nodes + edges
- `neo4j_writer.py`: batch write with `MERGE`, optional unique constraints
- `main.py`: CLI entrypoint

## Supported condition syntax

- `field not null`
- `field is null`
- `field != value`
- `field not indicates token`
- `field in (v1,v2,...)`
- `A AND B AND C`
- compatibility extension: `field indicates token` (for current auth rules)

## Built-in node ID strategy

- `Host`: `host`
- `Program`: `program`
- `Process`: `host|pid` (uses rule `subject_id_source/object_id_source` as pid source)
- `Interface`: `host|iface`
- `User`: normalized lowercase user string
- `IP`: IP string
- `Command`: command
- `Object`: object_name
- `Domain`: qname (lowercase)
- Other labels: fallback to `object_id_source/subject_id_source` field value

## Install

```bash
cd log_kg_builder
pip install -r requirements.txt
```

## Run with config (recommended)

Dry run with DNS:

```bash
python main.py --config configs/dns_example.json
```

Strict mode behavior:

- Nodes and edges are instantiated only from `relation.csv` template columns.
- Edge properties are copied only from each rule's `edge_properties`.
- Any field in `params_extracted.csv` not referenced by relation rules is ignored.

## Generate source-specific JSON config

Generate a dedicated config for a given `relation_csv + params_csv` pair:

```bash
python main.py ^
  --generate-config configs\dns_example.json ^
  --relation-csv ..\schemas\dns_relation.csv ^
  --params-csv ..\artifacts\params\inet_firewall_dnsmasq_3_params_extracted.csv
```

This command writes a source-specific JSON template with only base runtime options (`relation_csv`, `params_csv`, `dry_run`, `output_dir`, `neo4j`).

Write to Neo4j:

1. set env vars:
```bash
set NEO4J_URI=bolt://localhost:7687
set NEO4J_USER=neo4j
set NEO4J_PASSWORD=your_password
```
2. set `"dry_run": false` in config
3. run:
```bash
python main.py --config configs/dns_example.json
```

## Run with direct CLI args

```bash
python main.py ^
  --relation-csv ..\schemas\dns_relation.csv ^
  --params-csv ..\artifacts\params\inet_firewall_dnsmasq_3_params_extracted.csv ^
  --dry-run ^
  --output-dir ..\artifacts\graphs\sources\inet_firewall_dns
```

If writing to Neo4j directly from CLI:

```bash
python main.py ^
  --relation-csv ..\schemas\dns_relation.csv ^
  --params-csv ..\artifacts\params\inet_firewall_dnsmasq_3_params_extracted.csv ^
  --neo4j-uri bolt://localhost:7687 ^
  --neo4j-user neo4j ^
  --neo4j-password your_password ^
  --neo4j-database neo4j ^
  --create-constraints
```

## Reuse for audit/auth/dns/apache/vpn

Only replace:

- `relation_csv`
- `params_csv`

Everything else remains the same.

Examples:

- dns: `schemas/dns_relation.csv` + `artifacts/params/inet_firewall_dnsmasq_3_params_extracted.csv`
- auth: `schemas/auth_relation.csv` + `artifacts/params/intranet_server_auth_3_params_extracted.csv`
- audit: `schemas/audit_relation.csv` + `artifacts/params/internal_share_audit_3_params_extracted.csv`

## Output artifacts

If `output_dir` is provided, pipeline exports:

- `nodes.csv`
- `edges.csv`

Each row contains graph identity columns and `properties_json`.

## Neo4j behavior

- Node writes: `MERGE (n:Label {id: ...}) SET n += props`
- Edge writes: `MERGE (s)-[r:TYPE]->(o) SET r += props`
- Optional unique constraints:
  - `CREATE CONSTRAINT ... FOR (n:Label) REQUIRE n.id IS UNIQUE`
