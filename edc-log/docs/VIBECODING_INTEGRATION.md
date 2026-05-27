# Vibecoding 对接说明

本文档面向需要对接本项目的另一个系统。推荐把 `log_pipeline_agent/backend` 作为服务端能力使用，另一个项目通过 HTTP API 和 SSE 事件流集成。

## 启动方式

在项目根目录执行：

```powershell
python -m log_pipeline_agent api --host 127.0.0.1 --port 8787
python -m log_pipeline_agent frontend --host 127.0.0.1 --port 5173
```

前端地址：

```text
http://127.0.0.1:5173
```

API 地址：

```text
http://127.0.0.1:8787
```

前端只是静态页面，外部项目可以不使用它，直接调用后端 API。

## 标准调用流程

1. 调用 `GET /api/datasets` 获取可用数据集和默认图谱目录。
2. 调用 `POST /api/preflight` 做环境分析，检查输入、已有产物和 relation 覆盖。
3. 调用 `POST /api/plan` 让智能体生成 DAG 执行计划。
4. 调用 `POST /api/runs` 创建运行任务，返回 `job_id`。
5. 订阅 `GET /api/runs/{job_id}/events` 获取实时进度。
6. 调用 `GET /api/runs/{job_id}` 获取最终状态。
7. 调用 `GET /api/summary`、`POST /api/query-artifacts` 或 `POST /api/query-neo4j` 查看图谱结果。

## 运行请求示例

```json
{
  "mode": "smart",
  "task": "快速复用现有产物，构建并融合所有日志知识图谱",
  "datasets": ["inet_firewall_dns", "vpn_openvpn"],
  "limit_rows": 100,
  "max_workers": 3,
  "fused_graph_dir": "artifacts/graphs/fused",
  "write_neo4j": false,
  "neo4j_uri": "bolt://localhost:7687",
  "neo4j_user": "neo4j",
  "neo4j_password": "",
  "neo4j_database": "neo4j"
}
```

字段说明：

- `mode`: 建议固定为 `smart`，使用新智能体编排。
- `task`: 自然语言任务，planner 会据此选择数据集、判断是否复用已有产物。
- `datasets`: 为空时默认选择全部数据集。
- `skip_llm_steps`、`skip_param_extraction`、`skip_kg_build`: 外部项目通常不要传，交给 agent 根据 preflight 自动判断。
- `max_workers`: DAG 并发数，建议 1 到 4；需要调用 DeepSeek 时可调低。
- `write_neo4j`: 为 `true` 时会把融合图谱写入 Neo4j。前端中这是唯一需要勾选确认的执行选项。

创建运行：

```powershell
$body = @{
  mode = "smart"
  task = "快速复用现有产物，构建并融合 DNS 图谱"
  datasets = @("inet_firewall_dns")
  max_workers = 3
  limit_rows = 10
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/api/runs -Body $body -ContentType "application/json"
```

## SSE 事件流

订阅地址：

```text
GET /api/runs/{job_id}/events
```

事件类型：

```text
preflight_finished      环境分析完成
plan_created            DAG 计划已生成
plan_started            DAG 执行开始
node_started            单个节点开始
node_finished           单个节点完成
node_failed             单个节点失败
plan_finished           DAG 执行完成并写入运行记忆
job_completed           后端任务完成
job_failed              后端任务失败
```

浏览器端示例：

```javascript
const source = new EventSource("http://127.0.0.1:8787/api/runs/<job_id>/events");
source.addEventListener("node_finished", (event) => {
  const payload = JSON.parse(event.data);
  console.log(payload.payload.node.id, payload.payload.result);
});
```

## 图谱查询接口

本地 CSV 图谱查询：

```http
POST /api/query-artifacts
```

```json
{
  "graph_dir": "artifacts/graphs/fused",
  "label": "",
  "predicate": "",
  "contains": "dnsmasq",
  "limit": 20
}
```

Neo4j 自然语言查询：

```http
POST /api/query-neo4j
```

```json
{
  "config": "log_kg_query_agent/configs/query_agent_example.json",
  "question": "哪些程序和 DNS 活动有关？",
  "refresh_schema": true
}
```

## Neo4j 清库接口

清库是破坏性操作。接口要求确认文本必须精确为 `清空neo4j`。

```http
POST /api/neo4j/clear
```

```json
{
  "neo4j_uri": "bolt://localhost:7687",
  "neo4j_user": "neo4j",
  "neo4j_password": "your_password",
  "neo4j_database": "neo4j",
  "confirmation": "清空neo4j",
  "drop_schema": true,
  "batch_size": 10000
}
```

返回值会包含清理前后的节点数、关系数、约束数、索引数，以及被删除的 schema 名称。

## 对接建议

- 外部项目只依赖 `backend` API，不要直接调用根目录旧脚本。
- 长任务必须使用 SSE 监听进度，不建议同步等待 `POST /api/runs`。
- 如果只是演示或联调，建议只设置较小 `limit_rows`，让 agent 自动复用已有产物。
- 如果要重跑 DeepSeek 抽取，确保环境变量或请求体中提供 API key，并把 `max_workers` 调低。
- 运行结果以 `run_dir` 为准，可以把 `outcome.json`、`summary.md` 和 `validation_report.json` 作为跨项目交付物。
