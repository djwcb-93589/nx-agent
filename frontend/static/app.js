const state = {
  sources: [],
  sourceFolders: [],
  filtered: [],
  filteredFolders: [],
  activeSource: null,
  lastRunStatus: "idle",
  lastLiveRefreshAt: 0,
  poiEditorRows: [],
  poiValidationTimer: null,
  sourceTreeExpanded: new Set(),
  sourceTreeKnownRoots: new Set(),
  activeFolderKey: "",
  runScopeSelection: new Set(),
  runScopeTouched: false,
};

const els = {
  refreshButton: document.getElementById("refreshButton"),
  sourceFilter: document.getElementById("sourceFilter"),
  sourceList: document.getElementById("sourceList"),
  sourceCount: document.getElementById("sourceCount"),
  activeSource: document.getElementById("activeSource"),
  sampleInput: document.getElementById("sampleInput"),
  limitInput: document.getElementById("limitInput"),
  projectInput: document.getElementById("projectInput"),
  parseSourceList: document.getElementById("parseSourceList"),
  parseSourceCount: document.getElementById("parseSourceCount"),
  selectAllParseSourcesBtn: document.getElementById("selectAllParseSourcesBtn"),
  clearParseSourcesBtn: document.getElementById("clearParseSourcesBtn"),
  modelInput: document.getElementById("modelInput"),
  similaritySelect: document.getElementById("similaritySelect"),
  reflectionCheckbox: document.getElementById("reflectionCheckbox"),
  treeCheckbox: document.getElementById("treeCheckbox"),
  plannerCheckbox: document.getElementById("plannerCheckbox"),
  preserveCheckbox: document.getElementById("preserveCheckbox"),
  startRunButton: document.getElementById("startRunButton"),
  stopRunButton: document.getElementById("stopRunButton"),
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
  poiTable: document.getElementById("poiTable"),
  poiMeta: document.getElementById("poiMeta"),
  editPoiButton: document.getElementById("editPoiButton"),
  customerEventTable: document.getElementById("customerEventTable"),
  customerEventMeta: document.getElementById("customerEventMeta"),
  customerEventValidation: document.getElementById("customerEventValidation"),
  summaryTable: document.getElementById("summaryTable"),
  summaryMeta: document.getElementById("summaryMeta"),
  apiKeyInput: document.getElementById("apiKeyInput"),
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
  { tool: "ensure_schema", title: "准备字段库", desc: "匹配或生成 POI 字段库和规则库。" },
  { tool: "build_deep_group_tree", title: "深度分组", desc: "把相似日志聚成事件组。" },
  { tool: "parse_groups_with_memory_reflection", title: "模板解析", desc: "记忆命中、采样、模型调用、反思修正。" },
  { tool: "write_outputs", title: "写出结果", desc: "生成 CSV、分组树和 schema 文件。" },
];

const TOOL_LABELS = {
  glm_planner: "GLM 制定计划",
  deepseek_planner: "GLM 制定计划",
  group_planner: "选择事件组策略",
  read_raw_logs: "读取原始日志",
  preprocess_logs: "时间戳预处理",
  ensure_schema: "准备字段库",
  build_deep_group_tree: "构建分组树",
  parse_groups_with_memory_reflection: "解析所有事件组",
  parse_group: "解析事件组",
  write_outputs: "写出解析结果",
  source_run: "日志源完成",
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
  installCollapsiblePanels();
  installMaximizeButtons();
  await loadSources();
  await pollRunStatus();
  setInterval(() => pollRunStatus().catch(showError), 1000);
}

async function loadSources(options = {}) {
  const { reloadActive = false, silent = false } = options;
  const limit = encodeURIComponent(els.limitInput.value || "80");
  const [sources, folderPayload] = await Promise.all([
    fetchJson("/api/sources"),
    fetchJson(`/api/source-folders?limit=${limit}`),
  ]);
  state.sources = sources;
  state.sourceFolders = folderPayload.folders || [];
  seedSourceTreeExpansion();
  ensureActiveFolder();
  syncRunScopeWithSources();
  applyFilter();
  renderRunScopePicker();
  await loadSummary();
  if (state.activeSource && reloadActive && selectedRunSources().includes(state.activeSource)) {
    await selectSource(state.activeSource, false, { silent }).catch(showSourceError);
  } else if (!state.activeSource || !selectedRunSources().includes(state.activeSource)) {
    await refreshDisplayedSourceFromSelection({ silent }).catch(showSourceError);
  }
}

function applyFilter() {
  const query = els.sourceFilter.value.trim().toLowerCase();
  state.filtered = state.sources.filter((item) => sourceMatchesQuery(item, query));
  state.filteredFolders = state.sourceFolders.filter((folder) =>
    folderMatchesQuery(folder, query),
  );
  renderSources();
}

function renderSources() {
  els.sourceCount.textContent = `${state.sourceFolders.length} 个目录，${state.sources.length} 个日志源`;
  els.sourceList.innerHTML = "";
  if (state.filteredFolders.length === 0) {
    els.sourceList.innerHTML = '<div class="empty compact-empty">没有匹配的日志目录</div>';
    return;
  }
  const tree = buildSourceTree(state.filteredFolders, state.filtered);
  const fragment = document.createDocumentFragment();
  for (const child of tree.children.values()) {
    fragment.appendChild(renderSourceNode(child, 0));
  }
  els.sourceList.appendChild(fragment);
}

function syncRunScopeWithSources() {
  const available = new Set(state.sources.map((item) => item.source));
  const candidates = currentRunScopeCandidates();
  if (!state.runScopeTouched) {
    state.runScopeSelection = new Set(defaultRunScopeSelection(candidates));
    syncProjectInputFromRunScope();
    return;
  }
  state.runScopeSelection = new Set(
    [...state.runScopeSelection].filter((source) => available.has(source)),
  );
  syncProjectInputFromRunScope();
}

function renderRunScopePicker() {
  if (!els.parseSourceList) {
    return;
  }
  els.parseSourceList.innerHTML = "";
  if (state.sources.length === 0) {
    els.parseSourceList.innerHTML = '<div class="empty compact-empty">没有可选日志</div>';
    updateRunScopeCount();
    return;
  }
  const fragment = document.createDocumentFragment();
  const sortedSources = currentRunScopeCandidates();
  if (sortedSources.length === 0) {
    els.parseSourceList.innerHTML = '<div class="empty compact-empty">当前文件夹下没有日志文件</div>';
    updateRunScopeCount();
    return;
  }
  for (const item of sortedSources) {
    const label = document.createElement("label");
    label.className = "run-source-item";
    label.innerHTML = `
      <input class="parse-source-check" type="checkbox" value="${escapeHtml(item.source)}" ${
        state.runScopeSelection.has(item.source) ? "checked" : ""
      } />
      <span>
        ${escapeHtml(sourceDisplayName(item.source))}
        <small>${escapeHtml(sourceSegments(item.source).slice(0, -1).join(" / "))}</small>
      </span>
    `;
    const checkbox = label.querySelector("input");
    checkbox.addEventListener("change", () => {
      state.runScopeTouched = true;
      if (checkbox.checked) {
        state.runScopeSelection.add(item.source);
      } else {
        state.runScopeSelection.delete(item.source);
      }
      syncProjectInputFromRunScope();
      updateRunScopeCount();
      refreshDisplayedSourceFromSelection().catch(showSourceError);
    });
    fragment.appendChild(label);
  }
  els.parseSourceList.appendChild(fragment);
  updateRunScopeCount();
}

function setRunScopeSelection(sources) {
  state.runScopeTouched = true;
  state.runScopeSelection = new Set(sources);
  syncProjectInputFromRunScope();
  renderRunScopePicker();
  refreshDisplayedSourceFromSelection().catch(showSourceError);
}

function selectAllRunSources() {
  setRunScopeSelection(currentRunScopeCandidates().map((item) => item.source));
}

function clearRunSources() {
  setRunScopeSelection([]);
}

function selectSingleRunSource(source) {
  setRunScopeSelection(source ? [source] : []);
}

function selectedRunSources() {
  const selected = state.runScopeSelection;
  return currentRunScopeCandidates()
    .map((item) => item.source)
    .filter((source) => selected.has(source));
}

function syncProjectInputFromRunScope() {
  const selected = selectedRunSources();
  els.projectInput.value = selected.join(",");
}

function updateRunScopeCount() {
  if (!els.parseSourceCount) {
    return;
  }
  const candidates = currentRunScopeCandidates();
  const candidateSet = new Set(candidates.map((item) => item.source));
  const selected = selectedRunSources().filter((source) => candidateSet.has(source)).length;
  els.parseSourceCount.textContent = `${selected} / ${candidates.length}`;
}

function seedSourceTreeExpansion() {
  for (const folder of state.sourceFolders) {
    const segments = folderSegments(folder.folder);
    let key = "root";
    for (const segment of segments) {
      key = `${key}/${segment}`;
      if (!state.sourceTreeKnownRoots.has(key)) {
        state.sourceTreeKnownRoots.add(key);
        state.sourceTreeExpanded.add(key);
      }
    }
  }
}

function sourceMatchesQuery(item, query) {
  if (!query) {
    return true;
  }
  return [
    item.source,
    sourceDisplayName(item.source),
    sourceSegments(item.source).join("/"),
  ].some((value) => String(value || "").toLowerCase().includes(query));
}

function folderMatchesQuery(folder, query) {
  if (!query) {
    return true;
  }
  const folderKey = folderKeyFromFolder(folder.folder);
  const hasMatchingSource = state.filtered.some((item) =>
    sourceFolderKey(item.source).startsWith(folderKey),
  );
  return hasMatchingSource || [
    folder.folder,
    folder.label,
    folder.schema_type,
  ].some((value) => String(value || "").toLowerCase().includes(query));
}

function buildSourceTree(folders, items) {
  const root = createSourceTreeNode("root", "root");
  const sortedFolders = [...folders].sort((a, b) =>
    a.folder.localeCompare(b.folder, "zh-CN"),
  );
  const sortedItems = [...items].sort((a, b) => a.source.localeCompare(b.source, "zh-CN"));
  const nodesByKey = new Map([["root", root]]);
  for (const folder of sortedFolders) {
    let node = root;
    for (const segment of folderSegments(folder.folder)) {
      const key = `${node.key}/${segment}`;
      if (!node.children.has(segment)) {
        node.children.set(segment, createSourceTreeNode(segment, key));
      }
      node = node.children.get(segment);
      nodesByKey.set(key, node);
    }
    node.folder = folder;
  }
  for (const item of sortedItems) {
    const key = sourceFolderKey(item.source);
    const node = nodesByKey.get(key);
    if (node) {
      node.directSources.push(item);
    }
  }
  updateSourceNodeCounts(root);
  markSourceLeafFolders(root);
  return root;
}

function createSourceTreeNode(label, key) {
  return {
    label,
    key,
    children: new Map(),
    folder: null,
    directSources: [],
    isLeafFolder: false,
    total: 0,
    ready: 0,
  };
}

function updateSourceNodeCounts(node) {
  let total = node.directSources.length;
  let ready = node.directSources.filter((item) => item.output_available).length;
  for (const child of node.children.values()) {
    const counts = updateSourceNodeCounts(child);
    total += counts.total;
    ready += counts.ready;
  }
  node.total = total;
  node.ready = ready;
  return { total, ready };
}

function markSourceLeafFolders(node) {
  node.isLeafFolder = Boolean(node.folder && node.children.size === 0);
  for (const child of node.children.values()) {
    markSourceLeafFolders(child);
  }
}

function renderSourceNode(node, depth) {
  const active = nodeHasActiveSource(node);
  const hasChildren = node.children.size > 0;
  const isSelectableFolder = node.isLeafFolder;
  const expanded = hasChildren && state.sourceTreeExpanded.has(node.key);
  const wrapper = document.createElement("div");
  wrapper.className = `source-tree-node depth-${Math.min(depth, 4)}`;

  const button = document.createElement("button");
  button.type = "button";
  button.className =
    "source-folder" +
    (expanded ? " expanded" : "") +
    (active ? " has-active" : "") +
    (isSelectableFolder ? " selectable-folder" : "") +
    (!hasChildren ? " empty-folder" : "");
  button.innerHTML = `
    <span class="source-folder-caret">${hasChildren ? (expanded ? "▾" : "▸") : ""}</span>
    <span class="source-folder-label">${escapeHtml(node.label)}</span>
    <span class="source-folder-count">${node.ready}/${node.total}</span>
  `;
  button.setAttribute("aria-expanded", String(expanded));
  wrapper.appendChild(button);

  let children = null;
  if (hasChildren) {
    children = document.createElement("div");
    children.className = "source-tree-children";
    children.hidden = !expanded;
    children.classList.toggle("is-hidden", !expanded);
    for (const child of node.children.values()) {
      children.appendChild(renderSourceNode(child, depth + 1));
    }
    wrapper.appendChild(children);

    button.addEventListener("click", () => {
      const nextExpanded = !state.sourceTreeExpanded.has(node.key);
      if (nextExpanded) {
        state.sourceTreeExpanded.add(node.key);
      } else {
        state.sourceTreeExpanded.delete(node.key);
      }
      button.classList.toggle("expanded", nextExpanded);
      button.setAttribute("aria-expanded", String(nextExpanded));
      const caret = button.querySelector(".source-folder-caret");
      if (caret) {
        caret.textContent = nextExpanded ? "▾" : "▸";
      }
      children.hidden = !nextExpanded;
      children.classList.toggle("is-hidden", !nextExpanded);
    });
  } else if (isSelectableFolder) {
    button.addEventListener("click", () => selectSourceFolder(node.key).catch(showSourceError));
  }
  return wrapper;
}

function sourceSegments(source) {
  const parts = String(source || "")
    .replaceAll("\\", "/")
    .split("/")
    .filter(Boolean);
  if (!parts.length) {
    return [];
  }
  const fileName = parts.at(-1).replace(/\.log$/i, "");
  return [...parts.slice(0, -1), fileName];
}

function sourceDisplayName(source) {
  const fileName = String(source || "")
    .replaceAll("\\", "/")
    .split("/")
    .filter(Boolean)
    .at(-1) || "";
  return fileName.replace(/\.log$/i, "");
}

function expandSourcePath(source) {
  expandFolderKey(sourceFolderKey(source));
}

function nodeHasActiveSource(node) {
  if (node.key === state.activeFolderKey) {
    return true;
  }
  for (const child of node.children.values()) {
    if (nodeHasActiveSource(child)) {
      return true;
    }
  }
  return false;
}

function sourceFolderSegments(source) {
  const parts = String(source || "")
    .replaceAll("\\", "/")
    .split("/")
    .filter(Boolean);
  const folders = parts.slice(0, -1);
  return folders.length ? folders : ["根目录"];
}

function folderSegments(folder) {
  const parts = String(folder || "")
    .replaceAll("\\", "/")
    .split("/")
    .filter(Boolean);
  return parts.length ? parts : ["根目录"];
}

function sourceFolderKey(source) {
  return folderKeyFromSegments(sourceFolderSegments(source));
}

function folderKeyFromFolder(folder) {
  return folderKeyFromSegments(folderSegments(folder));
}

function folderKeyFromSegments(segments) {
  return `root/${segments.join("/")}`;
}

function expandFolderKey(folderKey) {
  const parts = String(folderKey || "").split("/").filter(Boolean);
  let key = parts.shift() || "root";
  for (const part of parts) {
    key = `${key}/${part}`;
    state.sourceTreeExpanded.add(key);
  }
}

function currentRunScopeCandidates() {
  if (!state.activeFolderKey) {
    return sortSourcesForPicker(state.sources);
  }
  return sortSourcesForPicker(
    state.sources.filter((item) => sourceFolderKey(item.source) === state.activeFolderKey),
  );
}

function sortSourcesForPicker(items) {
  return [...items].sort((a, b) =>
    sourceDisplayName(a.source).localeCompare(sourceDisplayName(b.source), "zh-CN"),
  );
}

function defaultRunScopeSelection(candidates = currentRunScopeCandidates()) {
  const preferred = candidates.find((item) => item.output_available) || candidates[0];
  return preferred ? [preferred.source] : [];
}

function currentFolderInfo() {
  return state.sourceFolders.find(
    (folder) => folderKeyFromFolder(folder.folder) === state.activeFolderKey,
  );
}

function ensureActiveFolder() {
  const folderKeys = new Set(state.sourceFolders.map((folder) => folderKeyFromFolder(folder.folder)));
  if (state.activeSource && folderKeys.has(sourceFolderKey(state.activeSource))) {
    state.activeFolderKey = sourceFolderKey(state.activeSource);
    expandFolderKey(state.activeFolderKey);
    return;
  }
  if (state.activeFolderKey && folderKeys.has(state.activeFolderKey)) {
    expandFolderKey(state.activeFolderKey);
    return;
  }
  const firstFolderWithLogs = state.sourceFolders.find((folder) => folder.direct_log_count > 0);
  const firstLeafFolder = state.sourceFolders.find((folder) => folder.log_count === folder.direct_log_count);
  const fallbackFolder = firstFolderWithLogs || firstLeafFolder || state.sourceFolders[0];
  state.activeFolderKey = fallbackFolder ? folderKeyFromFolder(fallbackFolder.folder) : "";
  if (state.activeFolderKey) {
    expandFolderKey(state.activeFolderKey);
  }
}

async function selectSourceFolder(folderKey) {
  if (state.activeFolderKey !== folderKey) {
    state.activeFolderKey = folderKey;
    state.runScopeTouched = false;
  }
  expandFolderKey(folderKey);
  const folderSources = currentRunScopeCandidates();
  state.runScopeSelection = new Set(defaultRunScopeSelection(folderSources));
  syncProjectInputFromRunScope();
  renderRunScopePicker();
  renderSources();
  if (!folderSources.length) {
    state.activeSource = null;
    renderEmptyFolderPayload();
    return;
  }
  await refreshDisplayedSourceFromSelection();
}

async function refreshDisplayedSourceFromSelection(options = {}) {
  const selected = selectedRunSources();
  if (!selected.length) {
    state.activeSource = null;
    renderSources();
    renderEmptyFolderPayload();
    return;
  }
  await selectSource(selected[0], false, options);
}

function renderEmptyFolderPayload() {
  const folder = currentFolderInfo();
  const poiSchema = folder?.poi_schema || {
    available: false,
    columns: [],
    rows: [],
    truncated: false,
  };
  const schemaMeta = {
    available: Boolean(folder?.schema_type),
    schema_type: folder?.schema_type || "",
    generated: false,
  };
  const emptyCsv = { available: false, columns: [], rows: [], truncated: false };
  const label = folder?.label || "未选择日志目录";
  els.activeSource.textContent = label;
  renderPayload({
    source: folder?.folder || "",
    input: { path: "", rows: [], truncated: false },
    output_dir: "",
    preprocessed: emptyCsv,
    group: emptyCsv,
    result: emptyCsv,
    result_file: "",
    group_tree: { available: false },
    schema_meta: schemaMeta,
    poi_schema: poiSchema,
    relation_schema: emptyCsv,
    poi_result: emptyCsv,
    customer_events: emptyCsv,
  });
}

async function selectSource(source, syncRunScope, options = {}) {
  const { silent = false } = options;
  const sourceChanged = state.activeSource !== source;
  state.activeSource = source;
  state.activeFolderKey = sourceFolderKey(source);
  if (sourceChanged) {
    expandSourcePath(source);
  }
  if (syncRunScope) {
    selectSingleRunSource(source);
  }
  renderRunScopePicker();
  renderSources();
  els.activeSource.textContent = sourceDisplayName(source);
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
    els.poiTable,
    els.customerEventTable,
  ].filter(Boolean)) {
    target.innerHTML = '<div class="empty">加载中</div>';
  }
}

function showSourceError(err) {
  const message = err.message || String(err);
  els.rawMeta.textContent = "加载失败";
  els.preMeta.textContent = "加载失败";
  els.resultMeta.textContent = "加载失败";
  els.poiMeta.textContent = "加载失败";
  els.customerEventMeta.textContent = "加载失败";
  els.customerEventValidation.textContent = "";
  const html = `<div class="empty">加载失败：${escapeHtml(message)}</div>`;
  els.rawInput.innerHTML = html;
  for (const target of [
    els.preprocessedTable,
    els.resultTable,
    els.poiTable,
    els.customerEventTable,
  ].filter(Boolean)) {
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

  renderLogTemplateCsv(els.resultTable, payload.result);
  els.resultMeta.textContent = payload.result.available
    ? `${payload.result_file} | ${metaText(payload.result)}`
    : "缺失";

  renderCsv(els.poiTable, payload.poi_schema);
  els.poiMeta.textContent = schemaMetaText(payload.schema_meta, payload.poi_schema);
  els.editPoiButton.disabled = !state.activeSource;
  renderFirewallPoiResult(payload);
  renderMetrics(payload);
}

function renderFirewallPoiResult(payload) {
  const poiResult = payload.poi_result || {};
  els.customerEventValidation.textContent = "";
  els.customerEventValidation.className = "event-validation-summary";
  if (!poiResult.available) {
    els.customerEventMeta.textContent = "缺失";
    els.customerEventTable.innerHTML = '<div class="empty">没有解析后的 POI 字段</div>';
    return;
  }
  const schemaFields = (payload.poi_schema?.rows || [])
    .map((row) => row.field)
    .filter((field) => field && poiResult.columns.includes(field));
  const candidateColumns = schemaFields;
  const candidateRows = (poiResult.rows || []).map((row) =>
    Object.fromEntries(candidateColumns.map((column) => [column, row[column] ?? ""])),
  );
  const columns = candidateColumns.filter((column) =>
    candidateRows.some((row) => hasDisplayValue(row[column])),
  );
  if (!columns.length) {
    els.customerEventMeta.textContent = "0 行 POI 字段";
    els.customerEventTable.innerHTML = '<div class="empty">没有有值的 POI 字段</div>';
    return;
  }
  const rows = candidateRows.map((row) =>
    Object.fromEntries(columns.map((column) => [column, row[column] ?? ""])),
  );
  renderTable(els.customerEventTable, columns, rows);
  els.customerEventMeta.textContent = poiResult.truncated
    ? `${rows.length}+ 行 POI 字段`
    : `${rows.length} 行 POI 字段`;
}

function hasDisplayValue(value) {
  return String(value ?? "").trim() !== "";
}

function renderMetrics(payload) {
  const resultRows = payload.result.available ? payload.result.rows.length : 0;
  const poiRows = payload.poi_schema.available ? payload.poi_schema.rows.length : 0;
  const metrics = [
    ["原始预览", payload.input.rows.length],
    ["解析结果", resultRows],
    ["POI 字段", poiRows || "无"],
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

async function startRun() {
  const apiKey = els.apiKeyInput.value.trim();
  if (!apiKey) {
    throw new Error("GLM API Key is required. Enter it in the frontend; .env is not used for parsing.");
  }
  const selectedSources = selectedRunSources();
  if (selectedSources.length === 0) {
    throw new Error("请至少勾选一个要解析的日志。");
  }
  syncProjectInputFromRunScope();
  const payload = {
    project: els.projectInput.value.trim(),
    sample: Number(els.sampleInput.value || 3),
    model: els.modelInput.value.trim() || "glm-5.2",
    similarity: els.similaritySelect.value,
    doSelfReflection: els.reflectionCheckbox.checked,
    writeGroupTree: els.treeCheckbox.checked,
    plannerEnabled: els.plannerCheckbox.checked,
    preserveExisting: els.preserveCheckbox.checked,
    api_key: apiKey,
  };
  const data = await postJson("/api/run/start", payload);
  renderRunStatus(data.status);
  state.lastLiveRefreshAt = 0;
  await loadSources({ reloadActive: true, silent: true });
}

async function stopRun() {
  const data = await postJson("/api/run/stop", {});
  renderRunStatus(data.status);
  els.runMessage.textContent = data.message;
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
    return `${source}：${data.schema_type || "schema"}，POI ${data.poi_count || 0} 个`;
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

function installCollapsiblePanels() {
  document.querySelectorAll("[data-collapsible-panel]").forEach((panel) => {
    if (panel.dataset.collapseInstalled === "1") {
      return;
    }
    const body = panel.querySelector(".collapsible-body");
    const button = panel.querySelector("[data-collapse-toggle]");
    if (!body || !button) {
      return;
    }
    const collapsedLabel = button.dataset.collapsedLabel || "展开";
    const expandedLabel = button.dataset.expandedLabel || "收起";
    const initiallyCollapsed = panel.classList.contains("is-collapsed");
    body.hidden = initiallyCollapsed;
    button.textContent = initiallyCollapsed ? collapsedLabel : expandedLabel;
    button.setAttribute("aria-expanded", String(!initiallyCollapsed));
    button.addEventListener("click", () => {
      const collapsed = panel.classList.toggle("is-collapsed");
      body.hidden = collapsed;
      button.textContent = collapsed ? collapsedLabel : expandedLabel;
      button.setAttribute("aria-expanded", String(!collapsed));
    });
    panel.dataset.collapseInstalled = "1";
  });
}

function installMaximizeButtons() {
  document.querySelectorAll(".panel, .run-panel").forEach((panel) => {
    if (panel.closest(".modal-panel") || panel.dataset.maxInstalled === "1") {
      return;
    }
    const hasDisplayContent = panel.querySelector(
      ".table-wrap, .log-preview, .trace-list",
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

function renderLogTemplateCsv(target, payload) {
  if (!payload || !payload.available) {
    target.innerHTML = '<div class="empty">没有文件</div>';
    return;
  }
  const columnMap = new Map((payload.columns || []).map((column) => [column.toLowerCase(), column]));
  const templateColumns = [
    { label: "LineId", aliases: ["lineid", "line_id"] },
    { label: "OriginalContent", aliases: ["originalcontent", "original_content"] },
    { label: "EventId", aliases: ["eventid", "event_id"] },
    {
      label: "LogTemplate",
      aliases: [
        "logtemplate",
        "log_template",
        "regextemplate",
        "regex_template",
        "eventtemplate",
        "event_template",
      ],
    },
    { label: "RegexPattern", aliases: ["regexpattern", "regex_pattern"] },
  ];
  const visibleColumns = templateColumns.filter((column) =>
    column.aliases.some((alias) => columnMap.has(alias)),
  );
  const rows = (payload.rows || []).map((row) => {
    const next = {};
    for (const column of visibleColumns) {
      const source = column.aliases.map((alias) => columnMap.get(alias)).find(Boolean);
      next[column.label] = source ? (row[source] ?? "") : "";
    }
    return next;
  });
  renderTable(target, visibleColumns.map((column) => column.label), rows);
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
  els.runMessage.textContent = message;
  console.error(err);
}

function bindEvents() {
  els.refreshButton.addEventListener("click", () =>
    loadSources({ reloadActive: true, silent: false }).catch(showError),
  );
  els.sourceFilter.addEventListener("input", applyFilter);
  els.selectAllParseSourcesBtn.addEventListener("click", selectAllRunSources);
  els.clearParseSourcesBtn.addEventListener("click", clearRunSources);
  els.startRunButton.addEventListener("click", () => startRun().catch(showError));
  els.stopRunButton.addEventListener("click", () => stopRun().catch(showError));
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
}

bootstrap().catch(showError);
