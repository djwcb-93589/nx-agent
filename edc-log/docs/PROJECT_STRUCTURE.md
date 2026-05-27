# 项目结构说明

本次整理保留了原有非 agent 实现的位置，只在其外层增加 agent 编排、后端 API 和前端工作台。这样可以复用已有脚本，也避免移动历史文件导致导入路径失效。

## 目录边界

```text
log_pipeline_agent/
  core/                 智能体核心能力
    dag.py              PipelinePlan / PipelineNode，描述可执行 DAG
    preflight.py        环境和产物分析，检查缺失文件、行数、schema 覆盖
    planner.py          根据任务文本、数据集和分析结果生成执行计划
    executor.py         DAG 调度执行器，支持独立数据集分支并发执行
    evaluator.py        融合图谱产物质量评估
    memory.py           每次运行的事件、计划、结果和摘要落盘
    neo4j_admin.py      Neo4j 清库管理工具
  backend/
    server.py           独立后端 API 服务，供前端或外部项目调用
  frontend/
    index.html          中文前端界面
    app.js              前端 API 调用和 SSE 实时进度监听
    app.css             前端样式
    server.py           静态前端服务
  runs/
    run_*/              每次智能体运行的记忆目录
  tools.py              对已有非 agent 脚本的工具封装
  agent.py              兼容旧线性 CLI 的编排器
  main.py               CLI 入口
```

保留的运行依赖：

```text
AIT/                    原始 3.csv 和 template2samples.json
schemas/                POI、relation 等 schema 资源
artifacts/              字段 JSON、mapped JSON、参数 CSV、图谱 CSV
log_kg_builder/         知识图谱构建工具
log_kg_query_agent/     Neo4j 自然语言图查询实现
edc/                    DeepSeek 字段语义与 schema 映射依赖
```

## 运行产物约定

智能体每次执行会在 `log_pipeline_agent/runs/run_YYYYMMDD_HHMMSS/` 写入：

```text
preflight.json          环境分析结果
plan.json               DAG 执行计划
events.jsonl            实时事件日志
validation_report.json  融合图谱质量评估
outcome.json            完整执行结果
summary.md              本次运行摘要
```

图谱构建默认输出：

```text
artifacts/graphs/sources/<dataset>/nodes.csv
artifacts/graphs/sources/<dataset>/edges.csv
artifacts/graphs/fused/nodes.csv
artifacts/graphs/fused/edges.csv
```

字段和参数产物统一放在：

```text
artifacts/field_semantics/pairs_*.json
artifacts/schema_mappings/schema_*.json
artifacts/mapped_pairs/pairs_*_mapped.json
artifacts/params/*_params_extracted.csv
```

## 当前执行模型

新的执行流程不再只是固定线性调用。后端会先执行 preflight 分析，再生成 DAG 计划，然后按依赖关系调度执行：

```text
环境分析 -> 计划生成 -> 多数据集分支并发执行 -> 图谱融合 -> 质量评估 -> 查询/写入 Neo4j
```

`max_workers` 控制并发数。互不依赖的数据集分支可以并发运行；融合图谱和写入 Neo4j 会等待所有依赖节点完成。
