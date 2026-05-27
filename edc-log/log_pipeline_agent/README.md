# log_pipeline_agent

`log_pipeline_agent` 是知识图谱构建阶段的主入口。合并后，它接收 LibreLog 解析出的 `3.csv`，自动分析已有产物，生成 DAG 执行计划，并按依赖关系补齐缺失步骤。

## 流程

1. `AIT/**/3.csv` -> `template2samples.json`
2. `template2samples.json` -> `artifacts/field_semantics/pairs_*.json`
3. `pairs_*.json` + POI schema -> `artifacts/schema_mappings/schema_*.json`
4. `pairs_*.json` + `schema_*.json` -> `artifacts/mapped_pairs/pairs_*_mapped.json`
5. mapped JSON + 解析日志 -> `artifacts/params/*_params_extracted.csv`
6. params CSV + `schemas/*_relation*.csv` -> `artifacts/graphs/sources/<dataset>/`
7. 多源图谱融合 -> `artifacts/graphs/fused/`
8. 可选写入 Neo4j，或执行本地/Neo4j 图查询

## CLI

```powershell
python -m log_pipeline_agent list-datasets
python -m log_pipeline_agent run
python -m log_pipeline_agent query-artifacts --contains dnsmasq --limit 5
```

写入 Neo4j 需要显式参数：

```powershell
python -m log_pipeline_agent run --write-neo4j `
  --neo4j-uri bolt://localhost:7687 `
  --neo4j-user neo4j `
  --neo4j-password your_password
```

## 前后端分离

独立调试本项目时可以启动：

```powershell
python -m log_pipeline_agent api --host 127.0.0.1 --port 8787
python -m log_pipeline_agent frontend --host 127.0.0.1 --port 5173
```

合并后的推荐入口在仓库根目录：

```powershell
python -m frontend.server --host 127.0.0.1 --port 8765
```

前端不再要求用户理解每个中间文件。Agent 会根据 preflight 结果判断已有产物是否完整，完整则复用，缺失则补齐。Neo4j 写入是唯一需要显式确认的执行选项。

## 核心模块

- `core/preflight.py`: 检查输入、规则和中间产物
- `core/planner.py`: 生成 DAG 计划并判断跳过或补齐步骤
- `core/executor.py`: 按 DAG 依赖执行，支持多数据集并发
- `core/memory.py`: 保存每次运行的 plan、events、outcome 和 summary
- `backend/server.py`: HTTP API 与 SSE 事件流
- `frontend/`: 独立静态前端
