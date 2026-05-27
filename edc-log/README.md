# 日志知识图谱智能体项目

本项目把 AIT 日志处理流程封装为知识图谱构建智能体。合并到主项目后，它的输入由 LibreLog 解析阶段自动提供：

- `result_deepseek/**/3.csv` 会同步到 `edc-log/AIT/**/3.csv`
- 主项目 `schemas/` 或解析输出目录中的 POI / relation schema 会同步到 `edc-log/schemas/`
- `log_pipeline_agent` 负责环境分析、DAG 计划、字段语义映射、参数抽取、单源图谱构建、多源图谱融合和可选 Neo4j 写入

API key、Neo4j 用户名和密码等敏感配置统一从仓库根目录 `.env` 或系统环境变量读取。`.env` 已加入 `.gitignore`，不要提交真实凭据。

## 推荐启动方式

在仓库根目录启动合并后的工作台：

```powershell
python -m frontend.server --host 127.0.0.1 --port 8765
```

打开：

```text
http://127.0.0.1:8765
```

该页面同时保留 LibreLog 解析结果展示和本项目的知识图谱构建、查询、产物查看界面。

## 独立启动方式

如果只调试本项目，也可以在 `edc-log/` 目录下启动原有前后端：

```powershell
python -m log_pipeline_agent api --host 127.0.0.1 --port 8787
python -m log_pipeline_agent frontend --host 127.0.0.1 --port 5173
```

## 关键目录

```text
log_pipeline_agent/      智能体、后端 API、前端页面
artifacts/               字段语义、schema 映射、参数、图谱产物
AIT/                     由 LibreLog 同步而来的 3.csv 和 template2samples.json
schemas/                 POI 和 relation 规则
log_kg_builder/          知识图谱构建工具
log_kg_query_agent/      Neo4j 自然语言查询工具
edc/                     DeepSeek 字段语义和 schema 映射依赖
docs/                    项目结构和对接说明
```

## 对接文档

- `docs/PROJECT_STRUCTURE.md`
- `docs/VIBECODING_INTEGRATION.md`
- `log_pipeline_agent/README.md`
