# NINGXXXXIA Log Agent

NINGXXXXIA Log Agent 是一个面向日志分析和知识图谱构建的前后端分离项目。项目将日志解析、字段抽取、图谱构建、图谱融合、图谱查询和 Neo4j 写入整合到同一个本地服务中，用户可以通过浏览器完成完整流程。

## 项目架构

```text
.
├── agent/                  # 日志解析 Agent：调度 LLM、分组、模板生成、schema 生成和运行轨迹
├── parser/                 # 日志解析基础能力：分组、相似度、正则和评估辅助逻辑
├── backend/                # 后端 API 服务，默认端口 8765
│   └── server.py           # 日志解析、图谱构建、查询和 Neo4j API 入口
├── frontend/               # 前端静态页面服务，默认端口 5173，并代理 /api 到后端
│   ├── server.py           # 静态页面服务和开发代理入口
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

对于 `full_dataset/firewallexample/` 下的防火墙日志，参数抽取完成后还会生成客户事件协议产物：

```text
customer_events.json
customer_event_validation.json
customer_events_rejected.jsonl
```

其中 `customer_events.json` 按 `schemas/firewall_customer_event_schema.json` 输出
`alarm_type=1..4` 的事件。日志中不存在的终端 MAC、责任人、部门和设备管理信息，
通过 `schemas/firewall_assets.csv` 与 `schemas/firewall_devices.csv` 补全；无法确认的数据
不会由模型猜测，而会进入校验警告或拒绝清单。前端选择防火墙日志源后，可直接预览并下载该 JSON。

项目附带 `full_dataset/firewallexample/customer_event_simulated.log`，包含 20 条模拟日志，
四种 `alarm_type` 各 5 条，用于覆盖客户协议要求但原始样例中缺少的字段。该文件与其他
`.log` 文件使用完全相同的日志解析、字段抽取和图谱构建流程。

## 环境准备

建议使用 Python 3.10 或更高版本。

```powershell
cd <repo>
pip install -r requirements.txt
```

GLM API Key 不再从 `.env` 读取，需要在前端页面的 `GLM API Key`
输入框中填写。`.env` 只用于可选的模型默认值、GLM/Z.AI base URL 和 Neo4j 连接：

```text
GLM_BASE_URL=https://api.z.ai/api/paas/v4/
GLM_MODEL=glm-5.2
GLM_PARAM_MODEL=glm-5.2

NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=
NEO4J_DATABASE=neo4j
```

`.env` 已加入 `.gitignore`，不要提交真实 Neo4j 用户名或密码。GLM API Key
只通过前端请求传入后端运行时，不会写入 `.env`。

## 启动项目

当前版本采用前后端分离启动方式，需要分别启动后端 API 和前端静态页面。

终端 1：启动后端 API 服务：

```powershell
python -m backend.server --host 127.0.0.1 --port 8765
```

终端 2：启动前端静态页面服务：

```powershell
python -m frontend.server --host 127.0.0.1 --port 5173
```

浏览器打开前端页面：

```text
http://127.0.0.1:5173
```

前端页面默认通过自身的 `/api/...` 路径访问接口，`frontend.server` 会把这些请求代理到后端 API：

```text
http://127.0.0.1:8765
```

两个服务的职责分别是：

- `frontend.server`：提供 `frontend/static/` 下的前端静态页面，并在开发环境把 `/api/...` 请求代理到后端。
- `backend.server`：只提供 `/api/...` 后端接口，包括日志解析、知识图谱构建、图谱产物查看、本地图谱查询、Neo4j 查询和清库 API。

如果后端不是默认地址，可在启动前端时指定：

```powershell
python -m frontend.server --host 127.0.0.1 --port 5173 --api_base http://127.0.0.1:8765
```

部署到其他服务器并从外部浏览器访问时，通常这样启动：

```powershell
python -m backend.server --host 0.0.0.0 --port 8765
python -m frontend.server --host 0.0.0.0 --port 5173 --api_base http://127.0.0.1:8765
```

然后打开：

```text
http://<服务器IP或域名>:5173
```

`frontend.server` 会把浏览器发到 `/api/...` 的请求从服务器侧代理到
`--api_base`，所以浏览器不会去访问自己电脑的 `127.0.0.1`。如果前后端不在同一台
服务器，把 `--api_base` 改成后端 API 的可达地址。

## 命令行运行日志解析

如果只需要在命令行运行日志解析：

```powershell
python evaluation.py --project all --sample 3 --write_group_tree --api_key <GLM API Key>
```

指定部分日志源：

```powershell
python evaluation.py --project "auth,dnsmasq.log,intranet_server" --sample 3 --write_group_tree --api_key <GLM API Key>
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
--api_key            GLM API Key，必须显式传入；不会从 .env 读取
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

如果要写入 Neo4j，需要先启动本地或远程 Neo4j，并在前端填写连接信息；也可以
把 Neo4j 连接默认值放在 `.env` 中。前端中 Neo4j 写入和清库操作都需要用户显式确认。

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
