const state = { dashboard: null, alerts: [], indicators: [], filter: "all", view: "overview", searchTimer: null };
const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
const statusLabel = (value) => ({ "in-progress": "In progress", acknowledged: "Acknowledged", resolved: "Resolved", closed: "Closed", new: "New" }[value] || value);
const severityName = (score) => score >= 90 ? "Critical" : score >= 70 ? "High" : score >= 45 ? "Medium" : "Low";
const scoreClass = (score) => score >= 90 ? "critical" : score >= 70 ? "high" : score >= 45 ? "medium" : "low";
const api = async (path, options = {}) => {
  const response = await fetch(path, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || `Request failed (${response.status})`);
  return result;
};

function showToast(message, detail = "") {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `${escapeHtml(message)}${detail ? `<small>${escapeHtml(detail)}</small>` : ""}`;
  $("#toast-region").append(toast);
  window.setTimeout(() => toast.remove(), 3400);
}

function formatTime(value) {
  const elapsed = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 60000));
  if (elapsed < 60) return `${elapsed}m ago`;
  if (elapsed < 1440) return `${Math.floor(elapsed / 60)}h ago`;
  return `${Math.floor(elapsed / 1440)}d ago`;
}

function filteredAlerts() {
  const search = $("#global-search").value.trim().toLowerCase();
  return state.alerts.filter((alert) => {
    const filterMatch = state.filter === "all" || alert.state === state.filter;
    const searchMatch = !search || [alert.value, alert.type, alert.category, alert.rule, alert.source, alert.assignee].join(" ").toLowerCase().includes(search);
    return filterMatch && searchMatch;
  });
}

function renderMetrics(metrics) {
  $("#metric-active").textContent = metrics.active_indicators;
  $("#metric-high").textContent = metrics.high_risk;
  $("#metric-open").textContent = metrics.open_alerts;
  $("#metric-unassigned").textContent = metrics.unassigned;
  $("#nav-alert-count").textContent = metrics.open_alerts;
  $("#queue-count").textContent = state.alerts.filter((item) => !["resolved", "closed"].includes(item.state)).length;
  $("#new-count").textContent = state.alerts.filter((item) => item.state === "new").length;
}

function renderAlerts() {
  const alerts = filteredAlerts();
  $("#alert-rows").innerHTML = alerts.slice(0, 6).map((alert) => `
    <tr data-alert-id="${alert.id}" tabindex="0" aria-label="Open alert ${escapeHtml(alert.value)} details">
      <td><span class="indicator-primary">${escapeHtml(alert.value)}</span><span class="indicator-meta">${escapeHtml(alert.type.replace("_", " "))} · ${escapeHtml(alert.country)}</span></td>
      <td><span class="score score-${scoreClass(alert.severity_score)}"><i></i>${alert.severity_score} <span>${severityName(alert.severity_score)}</span></span></td>
      <td><span class="rule-cell">${escapeHtml(alert.rule)}</span><span class="indicator-meta">${escapeHtml(alert.source)} · ${formatTime(alert.created_at)}</span></td>
      <td class="assignee-cell">${alert.assignee ? escapeHtml(alert.assignee) : '<span class="unassigned-label">Unassigned</span>'}</td>
      <td><span class="status-pill status-${escapeHtml(alert.state)}">${statusLabel(alert.state)}</span></td>
      <td><button class="row-more" aria-label="Open alert details">···</button></td>
    </tr>`).join("");
  $("#alert-empty").classList.toggle("hidden", alerts.length > 0);
  $("#showing-alert-count").textContent = Math.min(alerts.length, 6);
}

function renderSources(sources) {
  $("#source-list").innerHTML = sources.map((source) => `<div class="source-row"><div class="source-name">${escapeHtml(source.name)}<span class="source-kind">${escapeHtml(source.type)} · ${escapeHtml(source.updated)}</span></div><div class="source-state ${source.state.toLowerCase()}">${escapeHtml(source.state)}</div></div>`).join("");
}

function renderCategories(categories) {
  const max = Math.max(1, ...categories.map((item) => item.count));
  $("#category-chart").innerHTML = categories.map((item) => `<div class="category-item"><span class="category-name">${escapeHtml(item.category)}</span><div class="category-track"><div class="category-bar" style="width:${Math.max(5, Math.round(item.count / max * 100))}%"></div></div><span class="category-count">${item.count}</span></div>`).join("");
}

function renderTrend(trend) {
  const width = 720;
  const height = 150;
  const max = 20;
  const x = (index) => 8 + index * (width - 16) / Math.max(1, trend.length - 1);
  const y = (value) => height - 8 - value / max * (height - 20);
  const points = (key) => trend.map((item, index) => `${x(index)},${y(item[key])}`).join(" ");
  const linePoints = trend.map((item, index) => `${x(index)} ${y(item.alerts)}`).join(" L ");
  const area = `M ${x(0)} ${height - 8} L ${linePoints} L ${x(trend.length - 1)} ${height - 8} Z`;
  const grid = [0, 1, 2, 3, 4].map((index) => `<line class="chart-gridline" x1="0" y1="${8 + index * (height - 16) / 4}" x2="${width}" y2="${8 + index * (height - 16) / 4}"/>`).join("");
  const dots = trend.map((item, index) => `<circle class="chart-point" cx="${x(index)}" cy="${y(item.alerts)}" r="3"/>`).join("");
  $("#activity-chart").innerHTML = `<defs><linearGradient id="chartFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#c7f36a" stop-opacity=".17"/><stop offset="100%" stop-color="#c7f36a" stop-opacity="0"/></linearGradient></defs>${grid}<path class="chart-area" d="${area}"/><polyline class="chart-line-resolved" points="${points("resolved")}"/><polyline class="chart-line" points="${points("alerts")}"/>${dots}`;
  $("#chart-days").innerHTML = trend.map((item) => `<span>${escapeHtml(item.day)}</span>`).join("");
  $("#weekly-alert-total").textContent = trend.reduce((total, item) => total + item.alerts, 0);
}

async function loadDashboard() {
  try {
    state.dashboard = await api("/api/dashboard");
    state.alerts = state.dashboard.alerts;
    renderMetrics(state.dashboard.metrics);
    renderAlerts();
    renderSources(state.dashboard.sources);
    renderCategories(state.dashboard.categories);
    renderTrend(state.dashboard.trend);
    $(".footer-live").textContent = "API CONNECTED";
  } catch (error) {
    $(".footer-live").textContent = "API DISCONNECTED";
    showToast("Could not load ThreatLens data", error.message);
  }
}

async function loadIndicators() {
  const params = new URLSearchParams();
  const query = $("#global-search").value.trim();
  const type = $("#type-filter").value;
  if (query) params.set("q", query);
  if (type) params.set("type", type);
  try {
    const result = await api(`/api/indicators?${params}`);
    state.indicators = result.items;
    $("#indicator-rows").innerHTML = result.items.map((item) => `<tr data-indicator-id="${escapeHtml(item.id)}" tabindex="0"><td><span class="indicator-primary">${escapeHtml(item.value)}</span><span class="indicator-meta">${escapeHtml(item.country)} · last seen ${formatTime(item.last_seen)}</span></td><td>${escapeHtml(item.type.replaceAll("_", " "))}</td><td>${escapeHtml(item.category)}</td><td><span class="score score-${scoreClass(item.severity_score)}"><i></i>${item.severity_score} ${severityName(item.severity_score)}</span></td><td>${item.confidence}%</td><td>${escapeHtml(item.source)}</td><td><span class="tlp-label">TLP:${escapeHtml(item.tlp.toUpperCase())}</span></td></tr>`).join("");
    $("#registry-count").textContent = `${result.total} indicators · sorted by severity`;
  } catch (error) { showToast("Could not load indicators", error.message); }
}

function setView(view) {
  state.view = view;
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  const overview = view !== "indicators";
  $("#overview-panels").classList.toggle("hidden", !overview);
  $("#indicators-panel").classList.toggle("hidden", overview);
  $(".trend-panel").classList.toggle("hidden", view === "alerts");
  $(".sources-panel").classList.toggle("hidden", view === "alerts");
  $(".exposure-panel").classList.toggle("hidden", view === "alerts");
  const labels = { overview: ["Overview", "Good morning, Priya", "Here’s your threat landscape for today."], alerts: ["Alert queue", "Alert queue", "Prioritize, assign and investigate active detections."], indicators: ["Indicators", "Indicator registry", "Search and review canonical intelligence records."] }[view];
  $("#breadcrumb-current").textContent = labels[0];
  $("#page-title").innerHTML = `${escapeHtml(labels[1])}<span class="heading-period">.</span>`;
  $("#page-subtitle").textContent = labels[2];
  if (view === "indicators") loadIndicators();
}

function openDrawer(alert) {
  if (!alert) return;
  const drawer = $("#detail-drawer");
  const scoreClassName = scoreClass(alert.severity_score);
  $("#drawer-content").innerHTML = `
    <div class="drawer-indicator">${escapeHtml(alert.value)}</div>
    <div class="drawer-category">${escapeHtml(alert.category)} · ${escapeHtml(alert.type.replaceAll("_", " "))}</div>
    <div class="drawer-score"><span>Severity score</span><strong class="score-${scoreClassName}">${alert.severity_score}<small style="font:10px var(--sans); color:#89968d"> / 100 · ${severityName(alert.severity_score)}</small></strong></div>
    <div class="drawer-section"><h3>INTELLIGENCE CONTEXT</h3><div class="detail-grid">
      <div class="detail-field"><span>Confidence</span><b>${alert.confidence}%</b></div><div class="detail-field"><span>Source</span><b>${escapeHtml(alert.source)}</b></div>
      <div class="detail-field"><span>First reported</span><b>${formatTime(alert.created_at)}</b></div><div class="detail-field"><span>Handling</span><b>TLP:${escapeHtml(alert.tlp.toUpperCase())}</b></div>
      <div class="detail-field"><span>Geography</span><b>${escapeHtml(alert.country)}</b></div><div class="detail-field"><span>Assignee</span><b>${escapeHtml(alert.assignee || "Unassigned")}</b></div>
    </div></div>
    <div class="drawer-section"><h3>DETECTION</h3><div class="drawer-description"><b>${escapeHtml(alert.rule)}</b><br>${escapeHtml(alert.description)}</div></div>
    <div class="drawer-section"><h3>RECOMMENDED NEXT STEP</h3><div class="drawer-description">Review correlated internal activity, validate the source verdict, then update the alert status with investigation context.</div></div>
    <div class="drawer-actions"><button class="button button-quiet" data-drawer-action="assign">Assign to me</button><button class="button button-quiet" data-drawer-action="enrich">↗ Enrich</button><button class="button button-primary" data-drawer-action="advance">${alert.state === "new" ? "Acknowledge alert" : alert.state === "acknowledged" ? "Start investigation" : alert.state === "in-progress" ? "Resolve alert" : "Reopen alert"}</button></div>`;
  drawer.dataset.alertId = alert.id;
  drawer.setAttribute("aria-hidden", "false");
  drawer.classList.add("open");
  $("#drawer-backdrop").classList.remove("hidden");
}

function closeDrawer() {
  $("#detail-drawer").classList.remove("open");
  $("#detail-drawer").setAttribute("aria-hidden", "true");
  $("#drawer-backdrop").classList.add("hidden");
}

async function updateAlert(alertId, payload) {
  try {
    await api(`/api/alerts/${alertId}`, { method: "PATCH", body: JSON.stringify(payload) });
    showToast("Alert updated", "Change recorded in the audit log.");
    closeDrawer();
    await loadDashboard();
  } catch (error) { showToast("Alert update failed", error.message); }
}

function downloadCsv(filename, rows) {
  const csv = rows.map((row) => row.map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")).join("\r\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => setView(item.dataset.view)));
document.querySelectorAll(".filter-tab").forEach((item) => item.addEventListener("click", () => {
  state.filter = item.dataset.filter;
  document.querySelectorAll(".filter-tab").forEach((tab) => tab.classList.toggle("selected", tab === item));
  renderAlerts();
}));
$("#see-all-alerts").addEventListener("click", () => setView("alerts"));
$("#next-alerts").addEventListener("click", () => setView("alerts"));
$("#view-sources").addEventListener("click", () => showToast("Feed health", "5 sources healthy · MalwareBazaar is delayed."));
$("#notifications-button").addEventListener("click", () => showToast("Notifications", `${state.dashboard?.metrics.unassigned ?? 0} alerts are waiting for assignment.`));
$("#refresh-button").addEventListener("click", async () => { $("#refresh-button").classList.add("is-refreshing"); await loadDashboard(); if (state.view === "indicators") await loadIndicators(); $("#refresh-button").classList.remove("is-refreshing"); showToast("Intelligence refreshed", "Latest stored feed and alert data loaded."); });
$("#global-search").addEventListener("input", () => {
  window.clearTimeout(state.searchTimer);
  state.searchTimer = window.setTimeout(() => state.view === "indicators" ? loadIndicators() : renderAlerts(), 160);
});
$("#type-filter").addEventListener("change", loadIndicators);
document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); $("#global-search").focus(); }
  if (event.key === "Escape") closeDrawer();
});
$("#alert-rows").addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-alert-id]");
  if (row) openDrawer(state.alerts.find((item) => item.id === Number(row.dataset.alertId)));
});
$("#alert-rows").addEventListener("keydown", (event) => { if (event.key === "Enter" && event.target.matches("tr")) openDrawer(state.alerts.find((item) => item.id === Number(event.target.dataset.alertId))); });
$("#drawer-close").addEventListener("click", closeDrawer);
$("#drawer-backdrop").addEventListener("click", closeDrawer);
$("#drawer-content").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-drawer-action]");
  if (!button) return;
  const drawer = $("#detail-drawer");
  const alertId = Number(drawer.dataset.alertId);
  const alert = state.alerts.find((item) => item.id === alertId);
  if (button.dataset.drawerAction === "assign") return updateAlert(alertId, { assignee: "Priya Nair" });
  if (button.dataset.drawerAction === "enrich") {
    try {
      const result = await api(`/api/indicators/${encodeURIComponent(alert.indicator_id)}/enrich`, { method: "POST", body: "{}" });
      showToast("Enrichment complete", `${result.indicator.source} · confidence ${result.indicator.confidence}%`);
    } catch (error) { showToast("Enrichment failed", error.message); }
    return;
  }
  const next = { new: "acknowledged", acknowledged: "in-progress", "in-progress": "resolved", resolved: "new", closed: "new" }[alert.state];
  updateAlert(alertId, { state: next });
});
$("#export-button").addEventListener("click", () => {
  const payload = { generated_at: new Date().toISOString(), metrics: state.dashboard?.metrics, prioritized_alerts: state.alerts.slice(0, 6) };
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
  link.download = "threatlens-operations-report.json";
  link.click();
  URL.revokeObjectURL(link.href);
  showToast("Report exported", "Operations snapshot downloaded as JSON.");
});
$("#registry-export").addEventListener("click", async () => {
  if (!state.indicators.length) await loadIndicators();
  downloadCsv("threatlens-indicators.csv", [["value", "type", "category", "severity", "confidence", "tlp", "source", "country", "status"], ...state.indicators.map((item) => [item.value, item.type, item.category, item.severity_score, item.confidence, item.tlp, item.source, item.country, item.status])]);
  showToast("CSV exported", `${state.indicators.length} indicators included.`);
});

loadDashboard();