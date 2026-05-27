const state = {
  datasets: [],
  plan: null,
  job: null,
  eventSource: null,
  completed: 0,
  total: 0,
  defaultFusedGraphDir: "",
};

const eventLabels = {
  preflight_finished: "环境分析",
  plan_created: "计划生成",
  plan_started: "计划启动",
  node_started: "节点开始",
  node_finished: "节点完成",
  node_failed: "节点失败",
  plan_finished: "计划完成",
  job_completed: "任务完成",
  job_failed: "任务失败",
};

function $(id) {
  return document.getElementById(id);
}

function apiBase() {
  return ($("apiBase").value || "http://127.0.0.1:8787").replace(/\/$/, "");
}

async function api(path, options = {}) {
  const res = await fetch(`${apiBase()}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const payload = await res.json();
  if (!res.ok) {
    throw new Error(payload.error || `HTTP ${res.status}`);
  }
  return payload;
}

function selectedDatasets() {
  return [...document.querySelectorAll(".dataset-check:checked")].map((item) => item.value);
}

function requestPayload() {
  return {
    task: $("taskText").value.trim(),
    datasets: selectedDatasets(),
    api_key: $("apiKey").value.trim(),
    limit_rows: $("limitRows").value.trim(),
    max_workers: $("maxWorkers").value.trim() || 1,
    fused_graph_dir: $("fusedGraphDir").value.trim(),
    write_neo4j: $("writeNeo4j").checked,
    neo4j_uri: $("neo4jUri").value.trim(),
    neo4j_user: $("neo4jUser").value.trim(),
    neo4j_password: $("neo4jPassword").value,
    neo4j_database: $("neo4jDatabase").value.trim() || "neo4j",
    mode: "smart",
  };
}

async function bootstrap() {
  const saved = localStorage.getItem("logAgentApiBase");
  if (saved) $("apiBase").value = saved;
  await checkHealth();
  await loadDatasets();
  bindEvents();
}

async function checkHealth() {
  try {
    await api("/api/health");
    $("apiState").textContent = "已连接";
    $("apiState").className = "badge ok";
  } catch (err) {
    $("apiState").textContent = "未连接";
    $("apiState").className = "badge bad";
    throw err;
  }
}

async function loadDatasets() {
  const payload = await api("/api/datasets");
  state.datasets = payload.datasets || [];
  state.defaultFusedGraphDir = payload.default_fused_graph_dir || "";
  $("projectRoot").textContent = payload.project_root || "";
  $("datasetCount").textContent = `${state.datasets.length} 个数据集`;
  $("fusedGraphDir").value = state.defaultFusedGraphDir;
  renderDatasets();
  refreshSummary();
}

function renderDatasets() {
  const box = $("datasetList");
  box.innerHTML = "";
  for (const dataset of state.datasets) {
    const label = document.createElement("label");
    label.className = "dataset-item";
    label.innerHTML = `
      <input class="dataset-check" type="checkbox" value="${dataset.name}" checked />
      <span>${dataset.name}<small>${dataset.family}</small></span>
    `;
    box.appendChild(label);
  }
}

async function runPreflight() {
  const payload = await api("/api/preflight", {
    method: "POST",
    body: JSON.stringify(requestPayload()),
  });
  $("analysisOutput").textContent = JSON.stringify(payload, null, 2);
}

async function createPlan() {
  const payload = await api("/api/plan", {
    method: "POST",
    body: JSON.stringify(requestPayload()),
  });
  state.plan = payload.plan;
  $("analysisOutput").textContent = JSON.stringify(payload.preflight, null, 2);
  renderPlan(payload.plan);
}

function renderPlan(plan) {
  $("planId").textContent = `计划 ${plan.plan_id}`;
  const list = $("planList");
  list.innerHTML = "";
  for (const node of plan.nodes || []) {
    const item = document.createElement("div");
    item.className = "plan-node";
    item.innerHTML = `
      <b>${node.id}</b>
      <span>${node.tool} | ${node.dataset}</span><br />
      <span>依赖：${(node.deps || []).join(", ") || "无"}</span><br />
      <span>${node.reason || ""}</span>
    `;
    list.appendChild(item);
  }
}

async function startRun() {
  const payload = requestPayload();
  if (payload.datasets.length === 0) {
    $("analysisOutput").textContent = "至少选择一个数据集";
    return;
  }
  if (payload.write_neo4j && (!payload.neo4j_uri || !payload.neo4j_user || !payload.neo4j_password)) {
    $("analysisOutput").textContent = "已确认落库，但 Neo4j URI、用户或密码为空";
    return;
  }
  clearRunView();
  const job = await api("/api/runs", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  state.job = job;
  $("jobId").textContent = `任务 ${job.job_id}`;
  connectEvents(job.job_id);
}

function clearRunView() {
  $("timeline").innerHTML = "";
  $("resultList").innerHTML = "";
  state.completed = 0;
  state.total = state.plan ? state.plan.nodes.length : 1;
  updateProgress();
}

function connectEvents(jobId) {
  if (state.eventSource) state.eventSource.close();
  const source = new EventSource(`${apiBase()}/api/runs/${jobId}/events`);
  state.eventSource = source;
  for (const eventName of Object.keys(eventLabels)) {
    source.addEventListener(eventName, (evt) => {
      const event = JSON.parse(evt.data);
      handleEvent(event);
    });
  }
  source.onerror = () => source.close();
}

function handleEvent(event) {
  appendTimeline(event);
  if (event.type === "plan_created") {
    state.plan = event.payload;
    state.total = state.plan.nodes.length;
    renderPlan(state.plan);
    updateProgress();
  }
  if (event.type === "node_finished") {
    state.completed += 1;
    updateProgress();
    renderResult(event.payload.result);
  }
  if (event.type === "node_failed") {
    $("analysisOutput").textContent = JSON.stringify(event.payload, null, 2);
  }
  if (event.type === "job_completed") {
    state.completed = state.total;
    updateProgress();
    $("analysisOutput").textContent = JSON.stringify(event.payload.evaluation || event.payload, null, 2);
    refreshSummary();
    if (state.eventSource) state.eventSource.close();
  }
  if (event.type === "job_failed") {
    $("analysisOutput").textContent = event.payload.traceback || event.payload.message;
    if (state.eventSource) state.eventSource.close();
  }
}

function appendTimeline(event) {
  const item = document.createElement("div");
  item.className = "timeline-row";
  const payload = event.payload || {};
  const node = payload.node || {};
  item.innerHTML = `
    <span>${(event.time || "").split("T").pop()}</span>
    <b>${eventLabels[event.type] || event.type}</b>
    <span>${node.id || payload.message || payload.goal || event.type}</span>
  `;
  $("timeline").appendChild(item);
  $("timeline").scrollTop = $("timeline").scrollHeight;
}

function updateProgress() {
  const total = Math.max(1, state.total);
  const done = Math.min(state.completed, total);
  const percent = Math.round((done / total) * 100);
  $("progressText").textContent = `${done} / ${total}`;
  $("progressPercent").textContent = `${percent}%`;
  $("progressBar").style.width = `${percent}%`;
}

function renderResult(result) {
  if (!result) return;
  const item = document.createElement("div");
  item.className = "result-item";
  item.innerHTML = `<b>${result.tool}</b><span>${result.message || ""}</span>`;
  const actions = document.createElement("div");
  actions.className = "artifact-actions";
  for (const [name, path] of Object.entries(result.outputs || {})) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = `查看 ${name}`;
    btn.addEventListener("click", () => viewArtifact(path));
    actions.appendChild(btn);
  }
  item.appendChild(actions);
  $("resultList").prepend(item);
}

async function refreshSummary() {
  const graphDir = $("fusedGraphDir").value.trim() || state.defaultFusedGraphDir;
  if (!graphDir) return;
  const summary = await api(`/api/summary?graph_dir=${encodeURIComponent(graphDir)}`);
  const cards = [
    ["节点数", summary.node_count || 0],
    ["边数", summary.edge_count || 0],
    ["节点类型", Object.keys(summary.labels || {}).length],
    ["关系类型", Object.keys(summary.predicates || {}).length],
  ];
  $("summaryGrid").innerHTML = cards
    .map(([label, value]) => `<div class="summary-card"><b>${value}</b><span>${label}</span></div>`)
    .join("");
}

async function viewArtifact(path) {
  $("artifactPath").textContent = path;
  const payload = await api(`/api/artifact?path=${encodeURIComponent(path)}`);
  if (payload.kind === "directory") {
    $("artifactOutput").textContent = JSON.stringify(payload.entries, null, 2);
  } else {
    $("artifactOutput").textContent = payload.content || "";
  }
}

async function queryArtifacts() {
  const result = await api("/api/query-artifacts", {
    method: "POST",
    body: JSON.stringify({
      graph_dir: $("fusedGraphDir").value.trim() || state.defaultFusedGraphDir,
      label: $("queryLabel").value.trim(),
      predicate: $("queryPredicate").value.trim(),
      contains: $("queryContains").value.trim(),
      limit: $("queryLimit").value.trim() || 20,
    }),
  });
  $("queryOutput").textContent = result.message;
}

async function queryNeo4j() {
  const result = await api("/api/query-neo4j", {
    method: "POST",
    body: JSON.stringify({
      config: "log_kg_query_agent/configs/query_agent_example.json",
      question: $("neo4jQuestion").value.trim(),
      refresh_schema: true,
      api_key: $("apiKey").value.trim(),
      neo4j_uri: $("neo4jUri").value.trim(),
      neo4j_user: $("neo4jUser").value.trim(),
      neo4j_password: $("neo4jPassword").value,
    }),
  });
  $("queryOutput").textContent = `${result.message}\n\n${result.metrics?.cypher || ""}`;
}

async function clearNeo4j() {
  const confirmation = $("clearNeo4jConfirm").value.trim();
  if (confirmation !== "清空neo4j") {
    $("queryOutput").textContent = "确认文本不正确";
    return;
  }
  const result = await api("/api/neo4j/clear", {
    method: "POST",
    body: JSON.stringify({
      neo4j_uri: $("neo4jUri").value.trim(),
      neo4j_user: $("neo4jUser").value.trim(),
      neo4j_password: $("neo4jPassword").value,
      neo4j_database: $("neo4jDatabase").value.trim() || "neo4j",
      confirmation,
      drop_schema: true,
    }),
  });
  $("queryOutput").textContent = JSON.stringify(result, null, 2);
  $("clearNeo4jConfirm").value = "";
}

function bindEvents() {
  $("saveApiBtn").addEventListener("click", () => {
    localStorage.setItem("logAgentApiBase", apiBase());
    checkHealth().catch((err) => ($("analysisOutput").textContent = err.message));
  });
  $("selectAllBtn").addEventListener("click", () =>
    document.querySelectorAll(".dataset-check").forEach((item) => (item.checked = true)),
  );
  $("clearAllBtn").addEventListener("click", () =>
    document.querySelectorAll(".dataset-check").forEach((item) => (item.checked = false)),
  );
  $("preflightBtn").addEventListener("click", () => runPreflight().catch(showError));
  $("planBtn").addEventListener("click", () => createPlan().catch(showError));
  $("runBtn").addEventListener("click", () => startRun().catch(showError));
  $("refreshSummaryBtn").addEventListener("click", () => refreshSummary().catch(showError));
  $("artifactQueryBtn").addEventListener("click", () => queryArtifacts().catch(showError));
  $("neo4jQueryBtn").addEventListener("click", () => queryNeo4j().catch(showError));
  $("clearNeo4jBtn").addEventListener("click", () => clearNeo4j().catch(showError));
}

function showError(err) {
  $("analysisOutput").textContent = err.stack || err.message || String(err);
}

bootstrap().catch(showError);
