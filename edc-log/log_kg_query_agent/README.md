# log_kg_query_agent

LLM-powered query agent for the Neo4j log knowledge graph already built from `audit / auth / dns / apache` or other supported log families already loaded into Neo4j.

This project is separate from `log_kg_builder` and focuses on:

- schema extraction from the existing Neo4j graph
- prompt injection with graph schema
- Cypher generation from natural language
- read-only query execution
- answer generation from returned subgraph data

## Project layout

```text
log_kg_query_agent/
  benchmark.py
  benchmarks/
    current_graph_questions.json
  main.py
  requirements.txt
  configs/
    query_agent_example.json
  cache/
  query_agent/
    config.py
    cypher_guard.py
    deepseek_client.py
    engine.py
    neo4j_client.py
    prompts.py
    schema.py
    serializers.py
```

## Install

```powershell
cd log_kg_query_agent
pip install -r requirements.txt
```

## Config

Set environment variables:

```powershell
$env:NEO4J_URI = "bolt://localhost:7687"
$env:NEO4J_USER = "neo4j"
$env:NEO4J_PASSWORD = "your_password"
$env:ZAI_API_KEY = "your_glm_api_key"
```

Then use `configs/query_agent_example.json`.

## Phase coverage

Phase 1:
- live Neo4j schema extraction and cache
- schema injected into the Cypher generation prompt
- numbered prompt rules for decomposition, schema discipline, and world knowledge use

Phase 2:
- natural language question -> Cypher JSON plan
- read-only Cypher guard
- one-round repair loop on Neo4j execution error

Phase 3:
- execute Cypher on Neo4j
- serialize returned rows / nodes / relationships / paths
- send structured results back to LLM for final answer

## Commands

Print current schema:

```powershell
python main.py --config configs\query_agent_example.json --schema-only --refresh-schema
```

Run one question:

```powershell
python main.py `
  --config configs\query_agent_example.json `
  --question "Which programs run on host inet-firewall?" `
  --refresh-schema
```

Run the current benchmark question set:

```powershell
python benchmark.py `
  --config configs\query_agent_example.json `
  --questions-file benchmarks\current_graph_questions.json `
  --refresh-schema
```

## Notes

- Generated Cypher is restricted to read-only execution.
- Schema cache is saved under `cache/graph_schema.json`.
- Query run artifacts are saved under `cache/query_runs/`.
- Benchmark summaries are saved under `cache/benchmarks/`.
- The agent uses only the live graph schema plus the user's question; it does not modify the graph.
