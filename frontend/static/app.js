const state = {
  sources: [],
  filtered: [],
  activeSource: null,
  lastRunStatus: "idle",
  lastLiveRefreshAt: 0,
  fullRunWaitingForKg: false,
  kgDatasets: [],
  kgPlan: null,
  kgJob: null,
  kgEventSource: null,
  kgCompleted: 0,
  kgTotal: 0,
  defaultFusedGraphDir: "",
  poiEditorRows: [],
  poiValidationTimer: null,
};

const els = {
  refreshButton: document.getElementById("refreshButton"),
  syncKgButton: document.getElementById("syncKgButton"),
  sourceFilter: document.getElementById("sourceFilter"),
  sourceList: document.getElementById("sourceList"),
  sourceCount: document.getElementById("sourceCount"),
  kgDatasetList: document.getElementById("kgDatasetList"),
  selectAllKgBtn: document.getElementById("selectAllKgBtn"),
  clearAllKgBtn: document.getElementById("clearAllKgBtn"),
  activeSource: document.getElementById("activeSource"),
  sampleInput: document.getElementById("sampleInput"),
  limitInput: document.getElementById("limitInput"),
  projectInput: document.getElementById("projectInput"),
  modelInput: document.getElementById("modelInput"),
  similaritySelect: document.getElementById("similaritySelect"),
  reflectionCheckbox: document.getElementById("reflectionCheckbox"),
  treeCheckbox: document.getElementById("treeCheckbox"),
  plannerCheckbox: document.getElementById("plannerCheckbox"),
  preserveCheckbox: document.getElementById("preserveCheckbox"),
  mockCheckbox: document.getElementById("mockCheckbox"),
  startRunButton: document.getElementById("startRunButton"),
  stopRunButton: document.getElementById("stopRunButton"),
  fullRunButton: document.getElementById("fullRunButton"),
  runStatus: document.getElementById("runStatus"),
  runMessage: document.getElementById("runMessage"),
  parseProgressText: document.getElementById("parseProgressText"),
  progressBar: document.getElementById("progressBar"),
  stageFlow: document.getElementById("stageFlow"),
  traceList: document.getElementById("traceList"),
  runLog: document.getElementById("runLog"),
  metricStrip: document.getElementById("metricStrip"),
  rawInput: document.getElementById("rawInput"),
  rawMeta: document.getElementById("rawMeta"),
  preprocessedTable: document.getElementById("preprocessedTable"),
  preMeta: document.getElementById("preMeta"),
  resultTable: document.getElementById("resultTable"),
  resultMeta: document.getElementById("resultMeta"),
  groupTable: document.getElementById("groupTable"),
  groupMeta: document.getElementById("groupMeta"),
  treeTable: document.getElementById("treeTable"),
  treeMeta: document.getElementById("treeMeta"),
  poiTable: document.getElementById("poiTable"),
  poiMeta: document.getElementById("poiMeta"),
  editPoiButton: document.getElementById("editPoiButton"),
  relationTable: document.getElementById("relationTable"),
  relationMeta: document.getElementById("relationMeta"),
  summaryTable: document.getElementById("summaryTable"),
  summaryMeta: document.getElementById("summaryMeta"),
  kgApiState: document.getElementById("kgApiState"),
  kgTaskText: document.getElementById("kgTaskText"),
  kgLimitRows: document.getElementById("kgLimitRows"),
  kgMaxWorkers: document.getElementById("kgMaxWorkers"),
  kgApiKey: document.getElementById("kgApiKey"),
  fusedGraphDir: document.getElementById("fusedGraphDir"),
  kgForceCheckbox: document.getElementById("kgForceCheckbox"),
  writeNeo4j: document.getElementById("writeNeo4j"),
  neo4jUri: document.getElementById("neo4jUri"),
  neo4jUser: document.getElementById("neo4jUser"),
  neo4jPassword: document.getElementById("neo4jPassword"),
  neo4jDatabase: document.getElementById("neo4jDatabase"),
  preflightBtn: document.getElementById("preflightBtn"),
  planBtn: document.getElementById("planBtn"),
  kgRunBtn: document.getElementById("kgRunBtn"),
  kgProgressText: document.getElementById("kgProgressText"),
  kgProgressBar: document.getElementById("kgProgressBar"),
  kgRunMessage: document.getElementById("kgRunMessage"),
  kgTimeline: document.getElementById("kgTimeline"),
  planId: document.getElementById("planId"),
  planList: document.getElementById("planList"),
  analysisOutput: document.getElementById("analysisOutput"),
  refreshSummaryBtn: document.getElementById("refreshSummaryBtn"),
  kgSummaryGrid: document.getElementById("kgSummaryGrid"),
  kgResultList: document.getElementById("kgResultList"),
  queryLabel: document.getElementById("queryLabel"),
  queryPredicate: document.getElementById("queryPredicate"),
  queryContains: document.getElementById("queryContains"),
  queryLimit: document.getElementById("queryLimit"),
  neo4jQuestion: document.getElementById("neo4jQuestion"),
  artifactQueryBtn: document.getElementById("artifactQueryBtn"),
  neo4jQueryBtn: document.getElementById("neo4jQueryBtn"),
  queryOutput: document.getElementById("queryOutput"),
  clearNeo4jConfirm: document.getElementById("clearNeo4jConfirm"),
  clearNeo4jBtn: document.getElementById("clearNeo4jBtn"),
  artifactPath: document.getElementById("artifactPath"),
  artifactOutput: document.getElementById("artifactOutput"),
  poiEditorModal: document.getElementById("poiEditorModal"),
  closePoiEditorButton: document.getElementById("closePoiEditorButton"),
  poiEditorPath: document.getElementById("poiEditorPath"),
  poiValidationBox: document.getElementById("poiValidationBox"),
  poiEditorRows: document.getElementById("poiEditorRows"),
  addPoiRowButton: document.getElementById("addPoiRowButton"),
  savePoiButton: document.getElementById("savePoiButton"),
  viewerModal: document.getElementById("viewerModal"),
  closeViewerButton: document.getElementById("closeViewerButton"),
  viewerTitle: document.getElementById("viewerTitle"),
  viewerBody: document.getElementById("viewerBody"),
};

const PARSE_STAGES = [
  { tool: "read_raw_logs", title: "读取日志", desc: "找到并读取原始 .log 文件。" },
  { tool: "preprocess_logs", title: "预处理", desc: "抽取时间戳，保留原始内容映射。" },
  { tool: "ensure_schema", title: "准备字段库", desc: "匹配或生成 POI 字段库和 Relation 库。" },
  { tool: "build_deep_group_tree", title: "深度分组", desc: "把相似日志聚成事件组。" },
  { tool: "parse_groups_with_memory_reflection", title: "模板解析", desc: "记忆命中、采样、模型调用、反思修正。" },
  { tool: "write_outputs", title: "写出结果", desc: "生成 CSV、分组树和 schema 文件。" },
];

const TOOL_LABELS = {
  deepseek_planner: "DeepSeek 制定计划",
  group_planner: "选择事件组策略",
  read_raw_logs: "读取原始日志",
  preprocess_logs: "时间戳预处理",
  ensure_schema: "准备 POI/Relation",
  build_deep_group_tree: "构建分组树",
  parse_groups_with_memory_reflection: "解析所有事件组",
  parse_group: "解析事件组",
  write_outputs: "写出解析结果",
  source_run: "日志源完成",
};

const KG_TOOL_LABELS = {
  generate_template2samples: "生成模板样本",
  extract_field_semantics: "抽取字段语义",
  map_fields_to_poi_schema: "映射到 POI",
  merge_pairs_with_schema_mapping: "合并字段映射",
  extract_params_from_logs: "抽取参数 CSV",
  build_graph_for_dataset: "构建单源图谱",
  fuse_graph_results: "融合多源图谱",
  write_graph_to_neo4j: "写入 Neo4j",
};

const EVENT_LABELS = {
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

const API_BASE = resolveApiBase();

function resolveApiBase() {
  const explicit = String(window.LOG_AGENT_API_BASE || "").trim();
  if (explicit) {
    return explicit.replace(/\/+$/, "");
  }
  if (window.location.protocol === "file:") {
    return "http://127.0.0.1:8765";
  }
  return "";
}

function apiUrl(url) {
  if (/^https?:\/\//i.test(url)) {
    return url;
  }
  return `${API_BASE}${url}`;
}

function noCacheUrl(url) {
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}_=${Date.now()}`;
}

async function fetchJson(url) {
  const response = await fetch(noCacheUrl(apiUrl(url)), {
    cache: "no-store",
    headers: { "Cache-Control": "no-cache" },
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || `${response.status} ${response.statusText}`);
  }
  return data;
}

async function postJson(url, payload = {}) {
  const response = await fetch(noCacheUrl(apiUrl(url)), {
    method: "POST",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache",
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) {
    const err = new Error(data.error || data.message || `${response.status} ${response.statusText}`);
    err.payload = data;
    throw err;
  }
  return data;
}

async function bootstrap() {
  bindEvents();
  installMaximizeButtons();
  await Promise.allSettled([loadSources(), loadKgDatasets()]);
  await checkKgHealth();
  await refreshKgSummary();
  await pollRunStatus();
  setInterval(() => pollRunStatus().catch(showError), 1000);
}

async function checkKgHealth() {
  try {
    const payload = await fetchJson("/api/kg/health");
    if (payload.available) {
      els.kgApiState.textContent = "已连接";
      els.kgApiState.className = "status-pill ok";
    } else {
      els.kgApiState.textContent = "不可用";
      els.kgApiState.className = "status-pill bad";
      els.analysisOutput.textContent = payload.error || "知识图谱模块不可用";
    }
  } catch (err) {
    els.kgApiState.textContent = "不可用";
    els.kgApiState.className = "status-pill bad";
    throw err;
  }
}

async function loadSources(options = {}) {
  const { reloadActive = false, silent = false } = options;
  state.sources = await fetchJson("/api/sources");
  applyFilter();
  await loadSummary();
  if (state.activeSource && reloadActive) {
    await selectSource(state.activeSource, false, { silent }).catch(showSourceError);
  } else if (!state.activeSource && state.sources.length > 0) {
    await selectSource(state.sources[0].source, false, { silent }).catch(showSourceError);
  }
}

function applyFilter() {
  const query = els.sourceFilter.value.trim().toLowerCase();
  state.filtered = state.sources.filter((item) =>
    item.source.toLowerCase().includes(query),
  );
  renderSources();
}

function renderSources() {
  els.sourceCount.textContent = `${state.filtered.length} 个日志源`;
  els.sourceList.innerHTML = "";
  for (const item of state.filtered) {
    const button = document.createElement("button");
    button.type = "button";
    button.className =
      "source-item" + (item.source === state.activeSource ? " active" : "");
    button.innerHTML = `
      <div class="source-title">${escapeHtml(item.source)}</div>
      <div class="source-meta">
        <span class="badge">${formatBytes(item.size_bytes)}</span>
        <span class="badge ${item.output_available ? "ready" : "missing"}">
          ${item.output_available ? "已有解析输出" : "未解析"}
        </span>
        <span class="badge">${item.result_files.length} 个结果文件</span>
      </div>
    `;
    button.addEventListener("click", () => selectSource(item.source, true).catch(showSourceError));
    els.sourceList.appendChild(button);
  }
}

async function selectSource(source, syncRunScope, options = {}) {
  const { silent = false } = options;
  state.activeSource = source;
  if (syncRunScope) {
    els.projectInput.value = source;
  }
  renderSources();
  els.activeSource.textContent = source;
  if (!silent) {
    setLoading();
  }

  const sample = encodeURIComponent(els.sampleInput.value || "3");
  const limit = encodeURIComponent(els.limitInput.value || "80");
  const payload = await fetchJson(
    `/api/source?source=${encodeURIComponent(source)}&sample=${sample}&limit=${limit}`,
  );
  renderPayload(payload);
}

function setLoading() {
  els.rawInput.innerHTML = '<div class="empty">加载中</div>';
  for (const target of [
    els.preprocessedTable,
    els.resultTable,
    els.groupTable,
    els.treeTable,
    els.poiTable,
    els.relationTable,
  ]) {
    target.innerHTML = '<div class="empty">加载中</div>';
  }
}

function showSourceError(err) {
  const message = err.message || String(err);
  els.rawMeta.textContent = "加载失败";
  els.preMeta.textContent = "加载失败";
  els.resultMeta.textContent = "加载失败";
  els.groupMeta.textContent = "加载失败";
  els.treeMeta.textContent = "加载失败";
  els.poiMeta.textContent = "加载失败";
  els.relationMeta.textContent = "加载失败";
  const html = `<div class="empty">加载失败：${escapeHtml(message)}</div>`;
  els.rawInput.innerHTML = html;
  for (const target of [
    els.preprocessedTable,
    els.resultTable,
    els.groupTable,
    els.treeTable,
    els.poiTable,
    els.relationTable,
  ]) {
    target.innerHTML = html;
  }
  showError(err);
}

function renderPayload(payload) {
  const rawRows = payload.input.rows || [];
  els.rawMeta.textContent = payload.input.truncated
    ? `${rawRows.length}+ 行`
    : `${rawRows.length} 行`;
  els.rawInput.innerHTML = rawRows.length
    ? rawRows
        .map(
          (row) => `
      <div class="log-line">
        <span class="line-no">${row.Line}</span>
        <span class="line-content">${escapeHtml(row.Content)}</span>
      </div>`,
        )
        .join("")
    : '<div class="empty">没有原始日志预览</div>';

  renderCsv(els.preprocessedTable, payload.preprocessed);
  els.preMeta.textContent = metaText(payload.preprocessed);

  renderCsv(els.resultTable, payload.result);
  els.resultMeta.textContent = payload.result.available
    ? `${payload.result_file} | ${metaText(payload.result)}`
    : "缺失";

  renderCsv(els.groupTable, payload.group);
  els.groupMeta.textContent = metaText(payload.group);

  renderTree(payload.group_tree);
  renderCsv(els.poiTable, payload.poi_schema);
  els.poiMeta.textContent = schemaMetaText(payload.schema_meta, payload.poi_schema);
  els.editPoiButton.disabled = !state.activeSource;
  renderCsv(els.relationTable, payload.relation_schema);
  els.relationMeta.textContent = schemaMetaText(payload.schema_meta, payload.relation_schema);
  renderMetrics(payload);
}

function renderMetrics(payload) {
  const tree = payload.group_tree || {};
  const resultRows = payload.result.available ? payload.result.rows.length : 0;
  const groupRows = payload.group.available ? payload.group.rows.length : 0;
  const poiRows = payload.poi_schema.available ? payload.poi_schema.rows.length : 0;
  const relationRows = payload.relation_schema.available ? payload.relation_schema.rows.length : 0;
  const metrics = [
    ["原始预览", payload.input.rows.length],
    ["解析结果", resultRows],
    ["日志分组", groupRows],
    ["POI 字段", poiRows || "无"],
    ["关系规则", relationRows || "无"],
    ["树中分组", tree.available ? tree.group_count : "无"],
  ];
  els.metricStrip.innerHTML = metrics
    .map(
      ([label, value]) => `
      <div class="metric">
        <div class="metric-label">${label}</div>
        <div class="metric-value">${value}</div>
      </div>`,
    )
    .join("");
}

function renderTree(tree) {
  if (!tree || !tree.available) {
    els.treeMeta.textContent = "缺失";
    els.treeTable.innerHTML = '<div class="empty">没有 group_tree.json</div>';
    return;
  }
  els.treeMeta.textContent = `${tree.group_count} 个分组`;
  const rows = tree.clusters.map((cluster) => ({
    EventId: cluster.event_id,
    Count: cluster.count,
    EventTemplate: cluster.event_template,
    LineIds: (cluster.line_ids || []).slice(0, 12).join(", "),
  }));
  renderTable(els.treeTable, ["EventId", "Count", "EventTemplate", "LineIds"], rows);
}

async function loadSummary() {
  const payload = await fetchJson("/api/summary");
  if (!payload.available) {
    els.summaryMeta.textContent = "缺失";
    els.summaryTable.innerHTML = '<div class="empty">没有 summary 文件</div>';
    return;
  }
  const first = payload.files[0];
  els.summaryMeta.textContent = first.file;
  renderCsv(els.summaryTable, first);
}

async function startRun(options = {}) {
  const payload = {
    project: els.projectInput.value.trim() || "all",
    sample: Number(els.sampleInput.value || 3),
    model: els.modelInput.value.trim() || "deepseek-v4-flash",
    similarity: els.similaritySelect.value,
    doSelfReflection: els.reflectionCheckbox.checked,
    writeGroupTree: els.treeCheckbox.checked,
    plannerEnabled: els.plannerCheckbox.checked,
    preserveExisting: els.preserveCheckbox.checked,
    mockLlm: els.mockCheckbox.checked,
  };
  const data = await postJson("/api/run/start", payload);
  renderRunStatus(data.status);
  if (data.ok && options.full) {
    state.fullRunWaitingForKg = true;
    els.kgForceCheckbox.checked = true;
    els.kgRunMessage.textContent = "完整流程已启动：等待日志解析完成后自动构建图谱。";
  }
  state.lastLiveRefreshAt = 0;
  await loadSources({ reloadActive: true, silent: true });
}

async function stopRun() {
  const data = await postJson("/api/run/stop", {});
  renderRunStatus(data.status);
  els.runMessage.textContent = data.message;
  state.fullRunWaitingForKg = false;
}

async function pollRunStatus() {
  const status = await fetchJson("/api/run/status?tail=260");
  renderRunStatus(status);

  const now = Date.now();
  if (status.running && now - state.lastLiveRefreshAt > 2500) {
    state.lastLiveRefreshAt = now;
    await loadSources({ reloadActive: true, silent: true });
  }

  if (
    state.lastRunStatus === "running" &&
    ["succeeded", "failed", "stopped"].includes(status.status)
  ) {
    await loadSources({ reloadActive: true, silent: true });
  }
  if (
    state.fullRunWaitingForKg &&
    state.lastRunStatus === "running" &&
    status.status === "succeeded"
  ) {
    state.fullRunWaitingForKg = false;
    await syncKgInputs();
    await loadKgDatasets();
    await startKgRun();
  }
  if (state.fullRunWaitingForKg && ["failed", "stopped"].includes(status.status)) {
    state.fullRunWaitingForKg = false;
    els.kgRunMessage.textContent = "日志解析没有成功完成，图谱构建未启动。";
  }
  state.lastRunStatus = status.status;
}

function renderRunStatus(status) {
  const statusText = {
    idle: "空闲",
    running: "运行中",
    stopping: "停止中",
    stopped: "已停止",
    succeeded: "已完成",
    failed: "失败",
  }[status.status] || status.status;
  els.runStatus.textContent = statusText;
  els.runStatus.className =
    "status-pill" + (status.status === "failed" ? " bad" : status.status === "succeeded" ? " ok" : "");
  els.runMessage.textContent = buildRunMessage(status);
  els.startRunButton.disabled = status.running;
  els.fullRunButton.disabled = status.running;
  els.stopRunButton.disabled = !status.running;
  const progress = status.total_sources
    ? Math.min(100, Math.round((status.completed_sources / status.total_sources) * 100))
    : status.running
      ? 8
      : 0;
  els.progressBar.style.width = `${progress}%`;
  els.parseProgressText.textContent = `${progress}%`;
  els.runLog.textContent = (status.logs || []).join("\n");
  els.runLog.scrollTop = els.runLog.scrollHeight;
  renderStageFlow(status.traces || [], status);
  renderTrace(status.traces || []);
}

function buildRunMessage(status) {
  const parts = [status.message || ""];
  if (status.total_sources) {
    parts.push(`${status.completed_sources}/${status.total_sources} 个日志源`);
  }
  if (status.current_source) {
    parts.push(`当前：${status.current_source}`);
  }
  if (status.started_at) {
    parts.push(`开始：${status.started_at}`);
  }
  if (status.ended_at) {
    parts.push(`结束：${status.ended_at}`);
  }
  return parts.filter(Boolean).join(" | ");
}

function renderTrace(traces) {
  if (!traces.length) {
    els.traceList.innerHTML =
      '<div class="empty">还没有解析调度记录。运行解析后，这里会展示 Agent 的每一步动作。</div>';
    return;
  }
  els.traceList.innerHTML = traces
    .slice(-18)
    .map((trace) => {
      const detail = buildTraceDetail(trace);
      const message = buildTraceMessage(trace, detail);
      return `
      <div class="trace-item">
        <div class="trace-top">
          <span class="trace-tool">${escapeHtml(TOOL_LABELS[trace.tool] || trace.tool || "")}</span>
          <span class="trace-stage">${escapeHtml(stageName(trace.stage))}</span>
        </div>
        <div class="trace-message">${escapeHtml(message)}</div>
        ${detail ? `<div class="trace-detail">${escapeHtml(detail)}</div>` : ""}
      </div>`;
    })
    .join("");
  els.traceList.scrollTop = els.traceList.scrollHeight;
}

function renderStageFlow(traces, status) {
  const completed = new Set(
    traces
      .filter((trace) => trace.stage === "observe" || trace.stage === "complete")
      .map((trace) => trace.tool),
  );
  const dispatches = traces
    .filter((trace) => trace.stage === "dispatch")
    .map((trace) => trace.tool);
  const activeTool = status.running ? dispatches[dispatches.length - 1] : "";
  els.stageFlow.innerHTML = PARSE_STAGES.map((stage, index) => {
    const done = completed.has(stage.tool);
    const active =
      activeTool === stage.tool ||
      (activeTool === "parse_group" && stage.tool === "parse_groups_with_memory_reflection");
    const className = done ? "done" : active ? "active" : "";
    return `
      <div class="stage-card ${className}">
        <div class="stage-index">${index + 1}</div>
        <div>
          <div class="stage-title">${stage.title}</div>
          <div class="stage-desc">${stage.desc}</div>
        </div>
      </div>`;
  }).join("");
}

function buildTraceMessage(trace, detail) {
  if (trace.stage === "plan") return "模型已为当前日志源生成工具调度计划。";
  if (trace.stage === "dispatch") return `准备执行：${TOOL_LABELS[trace.tool] || trace.tool}`;
  if (trace.stage === "observe") return detail || "工具执行完成并返回结果。";
  if (trace.stage === "complete") return detail || "当前日志源解析完成。";
  return trace.message || "";
}

function buildTraceDetail(trace) {
  const data = trace.data || {};
  if (trace.tool === "read_raw_logs" && data.line_count !== undefined) {
    return `读取到 ${data.line_count} 行日志`;
  }
  if (trace.tool === "preprocess_logs") {
    return `处理 ${data.line_count || 0} 行，抽取时间戳 ${data.timestamp_count || 0} 行`;
  }
  if (trace.tool === "ensure_schema") {
    const source = data.generated ? "模型新生成" : "命中已有库";
    return `${source}：${data.schema_type || "schema"}，POI ${data.poi_count || 0} 个，Relation ${data.relation_count || 0} 条`;
  }
  if (trace.tool === "build_deep_group_tree") {
    return `形成 ${data.group_count || 0} 个日志组，覆盖 ${data.line_count || 0} 行`;
  }
  if (trace.tool === "group_planner") {
    return `事件组 ${data.event_id || ""}，包含 ${data.group_size || 0} 行`;
  }
  if (trace.tool === "parse_group") {
    return `解析 ${data.parsed_rows || 0} 行，当前记忆模板 ${data.memory_size || 0} 个`;
  }
  if (trace.tool === "write_outputs") {
    return `写出 ${data.row_count || 0} 行解析结果`;
  }
  if (trace.tool === "source_run") {
    return `识别 ${data.event_count || 0} 类事件，用时 ${data.total_time || ""}`;
  }
  return "";
}

function stageName(stage) {
  return { plan: "计划", dispatch: "调用工具", observe: "观察结果", complete: "完成" }[stage] || stage || "";
}

async function openPoiEditor() {
  if (!state.activeSource) {
    return;
  }
  const payload = await fetchJson(`/api/poi/schema?source=${encodeURIComponent(state.activeSource)}`);
  state.poiEditorRows = (payload.rows || []).map((row) => ({
    field: row.field || "",
    description: row.description || "",
  }));
  els.poiEditorPath.textContent = payload.active_path || payload.canonical_path || payload.local_path || "";
  renderPoiEditorRows();
  renderPoiValidation(payload.validation);
  els.poiEditorModal.hidden = false;
}

function closePoiEditor() {
  els.poiEditorModal.hidden = true;
}

function renderPoiEditorRows() {
  els.poiEditorRows.innerHTML = "";
  if (!state.poiEditorRows.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "没有 POI 字段";
    els.poiEditorRows.appendChild(empty);
    return;
  }
  state.poiEditorRows.forEach((row, index) => {
    const item = document.createElement("div");
    item.className = "poi-row";

    const fieldInput = document.createElement("input");
    fieldInput.value = row.field;
    fieldInput.placeholder = "field_name";
    fieldInput.addEventListener("input", () => {
      state.poiEditorRows[index].field = fieldInput.value;
      schedulePoiValidation();
    });

    const descInput = document.createElement("textarea");
    descInput.value = row.description;
    descInput.placeholder = "description";
    descInput.rows = 2;
    descInput.addEventListener("input", () => {
      state.poiEditorRows[index].description = descInput.value;
      schedulePoiValidation();
    });

    const removeButton = document.createElement("button");
    removeButton.type = "button";
    removeButton.className = "icon-button";
    removeButton.title = "删除";
    removeButton.textContent = "×";
    removeButton.addEventListener("click", () => {
      state.poiEditorRows.splice(index, 1);
      renderPoiEditorRows();
      schedulePoiValidation();
    });

    item.append(fieldInput, descInput, removeButton);
    els.poiEditorRows.appendChild(item);
  });
}

function addPoiRow() {
  state.poiEditorRows.push({ field: "", description: "" });
  renderPoiEditorRows();
  schedulePoiValidation();
}

function schedulePoiValidation() {
  clearTimeout(state.poiValidationTimer);
  state.poiValidationTimer = setTimeout(() => {
    validatePoiEditor().catch(showError);
  }, 250);
}

async function validatePoiEditor() {
  const validation = await postJson("/api/poi/validate", {
    source: state.activeSource,
    rows: state.poiEditorRows,
  });
  renderPoiValidation(validation);
  return validation;
}

function renderPoiValidation(validation, message = "") {
  const payload = validation || { ok: false, errors: ["等待校验"], warnings: [] };
  const lines = [];
  if (message) {
    lines.push({ type: "ok", text: message });
  }
  for (const error of payload.errors || []) {
    lines.push({ type: "error", text: error });
  }
  for (const warning of payload.warnings || []) {
    lines.push({ type: "warning", text: warning });
  }
  if (!lines.length) {
    lines.push({ type: "ok", text: `POI 校验通过，共 ${payload.field_count || 0} 个字段。` });
  }
  els.poiValidationBox.innerHTML = lines
    .map((line) => `<div class="validation-line ${line.type}">${escapeHtml(line.text)}</div>`)
    .join("");
  els.savePoiButton.disabled = !payload.ok;
}

async function savePoiEditor() {
  try {
    const result = await postJson("/api/poi/save", {
      source: state.activeSource,
      rows: state.poiEditorRows,
    });
    renderPoiValidation(result.validation, "POI 已保存。");
    await loadSources({ reloadActive: true, silent: true });
    await loadKgDatasets();
  } catch (err) {
    if (err.payload && err.payload.validation) {
      renderPoiValidation(err.payload.validation);
      return;
    }
    throw err;
  }
}

function installMaximizeButtons() {
  document.querySelectorAll(".panel, .run-panel").forEach((panel) => {
    if (panel.closest(".modal-panel") || panel.dataset.maxInstalled === "1") {
      return;
    }
    const hasDisplayContent = panel.querySelector(
      ".table-wrap, .log-preview, .output, .trace-list, .timeline, .plan-list, .result-list, .summary-grid",
    );
    const head = panel.querySelector(".panel-head");
    if (!hasDisplayContent || !head) {
      return;
    }
    let actions = head.querySelector(".panel-head-actions");
    if (!actions) {
      actions = document.createElement("div");
      actions.className = "panel-head-actions";
      head.appendChild(actions);
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = "max-button";
    button.title = "最大化";
    button.textContent = "⛶";
    button.addEventListener("click", () => openViewer(panel));
    actions.appendChild(button);
    panel.dataset.maxInstalled = "1";
  });
}

function openViewer(panel) {
  const title = panel.querySelector("h3")?.textContent?.trim() || "查看";
  const clone = document.createElement("div");
  clone.className = "viewer-copy";
  [...panel.children].forEach((child) => {
    if (child.classList.contains("panel-head")) {
      return;
    }
    clone.appendChild(child.cloneNode(true));
  });
  clone.querySelectorAll(".max-button").forEach((button) => button.remove());
  els.viewerTitle.textContent = title;
  els.viewerBody.innerHTML = "";
  els.viewerBody.appendChild(clone);
  els.viewerModal.hidden = false;
}

function closeViewer() {
  els.viewerModal.hidden = true;
  els.viewerBody.innerHTML = "";
}

async function syncKgInputs() {
  const payload = await postJson("/api/kg/sync", {});
  els.analysisOutput.textContent = JSON.stringify(payload, null, 2);
  return payload;
}

async function loadKgDatasets() {
  const payload = await fetchJson("/api/kg/datasets");
  if (!payload.available) {
    els.kgDatasetList.innerHTML = `<div class="empty">${escapeHtml(payload.error || "知识图谱模块不可用")}</div>`;
    return;
  }
  state.kgDatasets = payload.datasets || [];
  state.defaultFusedGraphDir = payload.default_fused_graph_dir || "";
  if (!els.fusedGraphDir.value && state.defaultFusedGraphDir) {
    els.fusedGraphDir.value = state.defaultFusedGraphDir;
  }
  renderKgDatasets();
}

function renderKgDatasets() {
  els.kgDatasetList.innerHTML = "";
  for (const dataset of state.kgDatasets) {
    const label = document.createElement("label");
    label.className = "dataset-item";
    label.innerHTML = `
      <input class="kg-dataset-check" type="checkbox" value="${escapeHtml(dataset.name)}" checked />
      <span>${escapeHtml(dataset.name)}<small>${escapeHtml(dataset.family)} | ${escapeHtml(shortPath(dataset.csv_path))}</small></span>
    `;
    els.kgDatasetList.appendChild(label);
  }
}

function selectedKgDatasets() {
  return [...document.querySelectorAll(".kg-dataset-check:checked")].map((item) => item.value);
}

function kgRequestPayload() {
  return {
    task: els.kgTaskText.value.trim(),
    datasets: selectedKgDatasets(),
    api_key: els.kgApiKey.value.trim(),
    limit_rows: els.kgLimitRows.value.trim(),
    max_workers: els.kgMaxWorkers.value.trim() || 1,
    fused_graph_dir: els.fusedGraphDir.value.trim(),
    write_neo4j: els.writeNeo4j.checked,
    neo4j_uri: els.neo4jUri.value.trim(),
    neo4j_user: els.neo4jUser.value.trim(),
    neo4j_password: els.neo4jPassword.value,
    neo4j_database: els.neo4jDatabase.value.trim() || "neo4j",
    force: els.kgForceCheckbox.checked,
    sync_inputs: true,
    mode: "smart",
  };
}

async function runPreflight() {
  const payload = await postJson("/api/kg/preflight", kgRequestPayload());
  els.analysisOutput.textContent = JSON.stringify(payload, null, 2);
}

async function createKgPlan() {
  const payload = await postJson("/api/kg/plan", kgRequestPayload());
  state.kgPlan = payload.plan;
  els.analysisOutput.textContent = JSON.stringify(payload.preflight, null, 2);
  renderKgPlan(payload.plan);
}

async function startKgRun() {
  const payload = kgRequestPayload();
  if (payload.datasets.length === 0) {
    els.analysisOutput.textContent = "至少选择一个图谱数据集。";
    return;
  }
  if (payload.write_neo4j && (!payload.neo4j_uri || !payload.neo4j_user || !payload.neo4j_password)) {
    els.analysisOutput.textContent = "已勾选写入 Neo4j；表单为空的连接项将从 .env 读取。";
  }
  clearKgRunView();
  const job = await postJson("/api/kg/runs", payload);
  state.kgJob = job;
  els.kgRunMessage.textContent = `图谱任务 ${job.job_id} 已启动。`;
  connectKgEvents(job.job_id);
}

function clearKgRunView() {
  if (state.kgEventSource) {
    state.kgEventSource.close();
    state.kgEventSource = null;
  }
  els.kgTimeline.innerHTML = "";
  els.kgResultList.innerHTML = "";
  state.kgCompleted = 0;
  state.kgTotal = state.kgPlan ? state.kgPlan.nodes.length : 0;
  updateKgProgress();
}

function connectKgEvents(jobId) {
  const source = new EventSource(apiUrl(`/api/kg/runs/${jobId}/events`));
  state.kgEventSource = source;
  for (const eventName of Object.keys(EVENT_LABELS)) {
    source.addEventListener(eventName, (evt) => {
      const event = JSON.parse(evt.data);
      handleKgEvent(event);
    });
  }
  source.onerror = () => source.close();
}

function handleKgEvent(event) {
  appendKgTimeline(event);
  if (event.type === "plan_created") {
    state.kgPlan = event.payload;
    state.kgTotal = (state.kgPlan.nodes || []).length;
    renderKgPlan(state.kgPlan);
    updateKgProgress();
  }
  if (event.type === "node_finished") {
    state.kgCompleted += 1;
    updateKgProgress();
    renderKgResult(event.payload.result);
  }
  if (event.type === "node_failed") {
    els.analysisOutput.textContent = JSON.stringify(event.payload, null, 2);
    els.kgRunMessage.textContent = "图谱 DAG 节点失败。";
  }
  if (event.type === "job_completed") {
    state.kgCompleted = state.kgTotal;
    updateKgProgress();
    els.analysisOutput.textContent = JSON.stringify(event.payload.evaluation || event.payload, null, 2);
    els.kgRunMessage.textContent = "知识图谱构建完成。";
    refreshKgSummary().catch(showError);
    if (state.kgEventSource) state.kgEventSource.close();
  }
  if (event.type === "job_failed") {
    els.analysisOutput.textContent = event.payload.traceback || event.payload.message || "图谱任务失败";
    els.kgRunMessage.textContent = "知识图谱构建失败。";
    if (state.kgEventSource) state.kgEventSource.close();
  }
}

function appendKgTimeline(event) {
  const item = document.createElement("div");
  item.className = "timeline-row";
  const payload = event.payload || {};
  const node = payload.node || {};
  const tool = KG_TOOL_LABELS[node.tool] || node.tool || payload.tool || "";
  item.innerHTML = `
    <span>${escapeHtml((event.time || "").split("T").pop())}</span>
    <b>${escapeHtml(EVENT_LABELS[event.type] || event.type)}</b>
    <span>${escapeHtml(node.dataset ? `${node.dataset} | ${tool}` : payload.message || payload.goal || event.type)}</span>
  `;
  els.kgTimeline.appendChild(item);
  els.kgTimeline.scrollTop = els.kgTimeline.scrollHeight;
}

function updateKgProgress() {
  const total = Math.max(0, state.kgTotal);
  const done = Math.min(state.kgCompleted, total || state.kgCompleted);
  const percent = total ? Math.round((done / total) * 100) : 0;
  els.kgProgressText.textContent = `${done} / ${total}`;
  els.kgProgressBar.style.width = `${percent}%`;
}

function renderKgPlan(plan) {
  if (!plan) return;
  els.planId.textContent = `计划 ${plan.plan_id || ""}`;
  els.planList.innerHTML = "";
  for (const node of plan.nodes || []) {
    const item = document.createElement("div");
    item.className = "plan-node";
    item.innerHTML = `
      <b>${escapeHtml(node.id)}</b>
      <span>${escapeHtml(KG_TOOL_LABELS[node.tool] || node.tool)} | ${escapeHtml(node.dataset)}</span><br />
      <span>依赖：${escapeHtml((node.deps || []).join(", ") || "无")}</span>
    `;
    els.planList.appendChild(item);
  }
}

function renderKgResult(result) {
  if (!result) return;
  const item = document.createElement("div");
  item.className = "result-item";
  item.innerHTML = `<b>${escapeHtml(KG_TOOL_LABELS[result.tool] || result.tool)}</b><span>${escapeHtml(result.message || "")}</span>`;
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
  els.kgResultList.prepend(item);
}

async function refreshKgSummary() {
  const graphDir = els.fusedGraphDir.value.trim() || state.defaultFusedGraphDir;
  if (!graphDir) return;
  const summary = await fetchJson(`/api/kg/summary?graph_dir=${encodeURIComponent(graphDir)}`);
  const cards = [
    ["节点数", summary.node_count || 0],
    ["关系数", summary.edge_count || 0],
    ["节点类型", Object.keys(summary.labels || {}).length],
    ["关系类型", Object.keys(summary.predicates || {}).length],
  ];
  els.kgSummaryGrid.innerHTML = cards
    .map(([label, value]) => `<div class="summary-card"><b>${value}</b><span>${label}</span></div>`)
    .join("");
}

async function viewArtifact(path) {
  els.artifactPath.textContent = path;
  const payload = await fetchJson(`/api/kg/artifact?path=${encodeURIComponent(path)}`);
  if (payload.kind === "directory") {
    els.artifactOutput.textContent = JSON.stringify(payload.entries, null, 2);
  } else {
    els.artifactOutput.textContent = payload.content || "";
  }
}

async function queryArtifacts() {
  const result = await postJson("/api/kg/query-artifacts", {
    graph_dir: els.fusedGraphDir.value.trim() || state.defaultFusedGraphDir,
    label: els.queryLabel.value.trim(),
    predicate: els.queryPredicate.value.trim(),
    contains: els.queryContains.value.trim(),
    limit: els.queryLimit.value.trim() || 20,
  });
  els.queryOutput.textContent = result.message;
}

async function queryNeo4j() {
  const result = await postJson("/api/kg/query-neo4j", {
    config: "log_kg_query_agent/configs/query_agent_example.json",
    question: els.neo4jQuestion.value.trim(),
    refresh_schema: true,
    api_key: els.kgApiKey.value.trim(),
    neo4j_uri: els.neo4jUri.value.trim(),
    neo4j_user: els.neo4jUser.value.trim(),
    neo4j_password: els.neo4jPassword.value,
  });
  els.queryOutput.textContent = `${result.message}\n\n${result.metrics?.cypher || ""}`;
}

async function clearNeo4j() {
  const confirmation = els.clearNeo4jConfirm.value.trim();
  if (confirmation !== "清空neo4j") {
    els.queryOutput.textContent = "确认文本不正确。";
    return;
  }
  const result = await postJson("/api/kg/neo4j/clear", {
    neo4j_uri: els.neo4jUri.value.trim(),
    neo4j_user: els.neo4jUser.value.trim(),
    neo4j_password: els.neo4jPassword.value,
    neo4j_database: els.neo4jDatabase.value.trim() || "neo4j",
    confirmation,
    drop_schema: true,
  });
  els.queryOutput.textContent = JSON.stringify(result, null, 2);
  els.clearNeo4jConfirm.value = "";
}

function renderCsv(target, payload) {
  if (!payload || !payload.available) {
    target.innerHTML = '<div class="empty">没有文件</div>';
    return;
  }
  renderTable(target, payload.columns, payload.rows);
}

function renderTable(target, columns, rows) {
  if (!rows || rows.length === 0) {
    target.innerHTML = '<div class="empty">没有数据行</div>';
    return;
  }
  target.innerHTML = `
    <table>
      <thead>
        <tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr>
      </thead>
      <tbody>
        ${rows
          .map(
            (row) => `
          <tr>
            ${columns
              .map((column) => `<td>${escapeHtml(row[column] ?? "")}</td>`)
              .join("")}
          </tr>`,
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function metaText(payload) {
  if (!payload || !payload.available) {
    return "缺失";
  }
  return payload.truncated ? `${payload.rows.length}+ 行` : `${payload.rows.length} 行`;
}

function schemaMetaText(meta, payload) {
  if (!payload || !payload.available) {
    return "缺失";
  }
  if (!meta || !meta.available) {
    return metaText(payload);
  }
  const source = meta.generated ? "新生成" : "已有";
  return `${meta.schema_type || "schema"} | ${source} | ${metaText(payload)}`;
}

function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = units.shift();
  while (value >= 1024 && units.length) {
    value /= 1024;
    unit = units.shift();
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${unit}`;
}

function shortPath(path) {
  const text = String(path || "").replaceAll("\\", "/");
  const parts = text.split("/");
  return parts.slice(-5).join("/");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showError(err) {
  const message = err.stack || err.message || String(err);
  if (els.analysisOutput) {
    els.analysisOutput.textContent = message;
  }
  console.error(err);
}

function bindEvents() {
  els.refreshButton.addEventListener("click", () =>
    loadSources({ reloadActive: true, silent: false }).catch(showError),
  );
  els.syncKgButton.addEventListener("click", async () => {
    await syncKgInputs();
    await loadKgDatasets();
    await refreshKgSummary();
  });
  els.sourceFilter.addEventListener("input", applyFilter);
  els.startRunButton.addEventListener("click", () => startRun().catch(showError));
  els.stopRunButton.addEventListener("click", () => stopRun().catch(showError));
  els.fullRunButton.addEventListener("click", () => startRun({ full: true }).catch(showError));
  els.editPoiButton.addEventListener("click", () => openPoiEditor().catch(showError));
  els.closePoiEditorButton.addEventListener("click", closePoiEditor);
  els.addPoiRowButton.addEventListener("click", addPoiRow);
  els.savePoiButton.addEventListener("click", () => savePoiEditor().catch(showError));
  els.closeViewerButton.addEventListener("click", closeViewer);
  document.querySelectorAll("[data-close-modal='poi']").forEach((item) =>
    item.addEventListener("click", closePoiEditor),
  );
  document.querySelectorAll("[data-close-modal='viewer']").forEach((item) =>
    item.addEventListener("click", closeViewer),
  );
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") {
      return;
    }
    if (!els.viewerModal.hidden) closeViewer();
    if (!els.poiEditorModal.hidden) closePoiEditor();
  });
  els.sampleInput.addEventListener("change", () => {
    if (state.activeSource) selectSource(state.activeSource, false).catch(showSourceError);
  });
  els.limitInput.addEventListener("change", () => {
    if (state.activeSource) selectSource(state.activeSource, false).catch(showSourceError);
  });
  els.selectAllKgBtn.addEventListener("click", () =>
    document.querySelectorAll(".kg-dataset-check").forEach((item) => (item.checked = true)),
  );
  els.clearAllKgBtn.addEventListener("click", () =>
    document.querySelectorAll(".kg-dataset-check").forEach((item) => (item.checked = false)),
  );
  els.preflightBtn.addEventListener("click", () => runPreflight().catch(showError));
  els.planBtn.addEventListener("click", () => createKgPlan().catch(showError));
  els.kgRunBtn.addEventListener("click", () => startKgRun().catch(showError));
  els.refreshSummaryBtn.addEventListener("click", () => refreshKgSummary().catch(showError));
  els.artifactQueryBtn.addEventListener("click", () => queryArtifacts().catch(showError));
  els.neo4jQueryBtn.addEventListener("click", () => queryNeo4j().catch(showError));
  els.clearNeo4jBtn.addEventListener("click", () => clearNeo4j().catch(showError));
}

bootstrap().catch(showError);
