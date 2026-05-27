# NINGXXXXIA Log Agent

NINGXXXXIA Log Agent 是一个面向日志分析和知识图谱构建的前后端分离项目。项目将日志解析、字段抽取、图谱构建、图谱融合、图谱查询和 Neo4j 写入整合到同一个本地服务中，用户可以通过浏览器完成完整流程。

## 项目架构

```text
.
├── agent/                  # 日志解析 Agent：调度 LLM、分组、模板生成、schema 生成和运行轨迹
├── parser/                 # 日志解析基础能力：分组、相似度、正则和评估辅助逻辑
├── frontend/               # 集成前端与本地后端服务，默认只启动一个端口
│   ├── server.py           # HTTP API + 静态页面服务入口
│   └── static/             # 前端页面资源
├── edc-log/                # 知识图谱构建子模块
│   ├── log_pipeline_agent/ # 图谱流水线 Agent：预检查、DAG 计划、执行、查询和 Neo4j 管理
│   ├── log_kg_builder/     # CSV 到知识图谱的构建逻辑
│   ├── log_kg_query_agent/ # Neo4j 自然语言查询逻辑
│   ├── schemas/            # 图谱构建使用的 POI / relation schema
│   └── docs/               # edc-log 子模块说明文档
├── full_dataset/           # 原始日志输入目录
├── result_deepseek/        # 日志解析输出目录，本地生成，不建议提交 Git
├── schemas/                # 当前项目使用的 POI / relation schema
├── evaluation.py           # 命令行日志解析入口
├── env_utils.py            # .env 加载工具
├── requirements.txt        # Python 依赖
├── .env.example            # 环境变量示例
└── .gitignore              # Git 忽略规则
```

## 处理流程

项目主流程分为两段：

1. 日志解析：读取 `full_dataset/` 下的原始 `.log` 文件，生成 `preprocessed.csv`、`group.csv`、`3.csv`、`poi_schema.csv`、`relation_schema.csv` 等结果。
2. 知识图谱构建：将解析结果同步到 `edc-log/AIT/` 和 `edc-log/schemas/`，然后执行预检查、DAG 计划、字段抽取、单源图谱构建、多源图谱融合、图谱查询和可选 Neo4j 写入。

前端页面会把这两段流程放在一个界面中展示，用户不需要理解中间文件细节，也可以查看每一步生成的结果和运行日志。

## 环境准备

建议使用 Python 3.10 或更高版本。

```powershell
cd "E:\6服务器\NINGXXXXIA-main"
pip install -r requirements.txt
```

首次运行前复制环境变量模板：

```powershell
Copy-Item .env.example .env
```

然后在 `.env` 中填写本地配置：

```text
DEEPSEEK_API_KEY=
DS_TOKEN=${DEEPSEEK_API_KEY}
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_PARAM_MODEL=deepseek-chat

NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=
NEO4J_DATABASE=neo4j
```

`.env` 已加入 `.gitignore`，不要提交真实 API Key、Neo4j 用户名或密码。

## 启动项目

当前集成版本只需要启动一个服务端口：

```powershell
cd "E:\6服务器\NINGXXXXIA-main"
python -m frontend.server --host 127.0.0.1 --port 8765
```

浏览器打开：

```text
http://127.0.0.1:8765
```

该服务同时提供：

- 前端静态页面
- 日志解析 API
- 知识图谱构建 API
- 图谱产物查看 API
- 本地图谱查询 API
- Neo4j 查询和清库 API

## 命令行运行日志解析

如果只需要在命令行运行日志解析：

```powershell
python evaluation.py --project all --sample 3 --write_group_tree
```

指定部分日志源：

```powershell
python evaluation.py --project "auth,dnsmasq.log,intranet_server" --sample 3 --write_group_tree
```

不调用 LLM 的本地冒烟测试：

```powershell
python evaluation.py --input_dir .tmp_agent_dataset --output_dir .tmp_agent_result --mock_llm --write_group_tree
```

常用参数：

```text
--input_dir          原始日志目录，默认 full_dataset/
--output_dir         解析结果目录，默认 result_deepseek/
--schemas_dir        schema 目录，默认 schemas/
--project            要处理的日志源，默认 all
--sample             输出样本编号，默认 3
--model              LLM 模型名
--mock_llm           使用本地模拟结果，不调用大模型
--write_group_tree   输出分组树 JSON
--disable_planner    关闭 LLM 计划器，使用默认执行计划
```

## 知识图谱功能

知识图谱相关能力位于 `edc-log/` 下，通常通过集成前端调用。主要能力包括：

- 检查日志解析结果和 schema 是否完整
- 自动生成图谱构建 DAG 计划
- 抽取日志参数字段
- 构建单源日志图谱
- 融合多源日志图谱
- 查看节点、边和图谱摘要
- 对本地图谱产物进行简单查询
- 可选写入 Neo4j
- 基于 Neo4j 执行自然语言图查询
- 按确认文本清空 Neo4j 当前数据库

如果要写入 Neo4j，需要先启动本地或远程 Neo4j，并在 `.env` 中配置连接信息。前端中 Neo4j 写入和清库操作都需要用户显式确认。

## 输入与输出目录

默认输入目录：

```text
full_dataset/
```

默认日志解析输出目录：

```text
result_deepseek/
```

默认知识图谱输入同步目录：

```text
edc-log/AIT/
edc-log/schemas/
```

默认图谱构建输出目录由 `edc-log/log_pipeline_agent/config.py` 中的配置决定。生成的大体积数据和运行产物已经在 `.gitignore` 中忽略，不建议提交到 GitHub。

## Git 提交说明

以下内容不应提交：

```text
.env
result_deepseek/
edc-log/AIT/
edc-log/artifacts/
AIT/
artifacts/
log_output/
output/
```

提交前建议检查：

```powershell
git status --short
```

如果看到大 CSV、运行输出、API Key 或 Neo4j 密码，应先从暂存区移除再提交。
