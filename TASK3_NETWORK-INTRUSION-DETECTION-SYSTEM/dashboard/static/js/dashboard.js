/* PyNIDS dashboard front-end: polling + vanilla SVG charts (no libraries). */

"use strict";

const $ = (id) => document.getElementById(id);
const state = { categories: [], timer: null };

const SEV_COLORS = { 4: "#ef4444", 3: "#f59e0b", 2: "#06b6d4", 1: "#64748b" };
const SEV_NAMES = { 4: "Critical", 3: "High", 2: "Medium", 1: "Low" };

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function showToast(message) {
  let toast = $("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.remove("show"), 3200);
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`${url} -> HTTP ${response.status}`);
  return response.json();
}

/* ============================ charts ============================ */

function svgEl(html) {
  const template = document.createElement("template");
  template.innerHTML = html.trim();
  return template.content.firstChild;
}

function chartTimeline(series) {
  const el = $("chartTimeline");
  el.innerHTML = "";
  if (!series.length) { el.textContent = "no data"; return; }

  const W = 620, H = 190, PAD_L = 34, PAD_B = 22, PAD_T = 10;
  const width = W - PAD_L - 10, height = H - PAD_B - PAD_T;
  const max = Math.max(3, ...series.map((s) => s.count));
  const x = (i) => PAD_L + (width * i) / (series.length - 1 || 1);
  const y = (v) => PAD_T + height - (height * v) / max;

  const svg = svgEl(`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet"></svg>`);

  // gridlines + y labels
  for (let v = 0; v <= max; v += Math.ceil(max / 3)) {
    const gy = y(v);
    svg.appendChild(svgEl(
      `<line x1="${PAD_L}" y1="${gy}" x2="${W - 10}" y2="${gy}" stroke="#1e2c47" stroke-width="1"/>`));
    svg.appendChild(svgEl(
      `<text x="${PAD_L - 6}" y="${gy + 3}" fill="#7c8aa5" font-size="9" text-anchor="end">${v}</text>`));
  }
  // x labels (4 ticks)
  for (const frac of [0, 0.33, 0.66, 0.99]) {
    const i = Math.round(frac * (series.length - 1));
    const d = new Date(series[i].ts * 1000);
    const label = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    svg.appendChild(svgEl(
      `<text x="${x(i)}" y="${H - 6}" fill="#7c8aa5" font-size="9" text-anchor="middle">${label}</text>`));
  }
  // area + line
  const points = series.map((s, i) => `${x(i)},${y(s.count)}`).join(" ");
  svg.appendChild(svgEl(
    `<polygon points="${PAD_L},${y(0)} ${points} ${x(series.length - 1)},${y(0)}"
       fill="rgba(56,189,248,.14)"/>`));
  svg.appendChild(svgEl(
    `<polyline points="${points}" fill="none" stroke="#38bdf8" stroke-width="2"
       stroke-linejoin="round"/>`));
  // severity spikes highlighted
  series.forEach((s, i) => {
    if (s.count > 0 && s.max_severity >= 3) {
      svg.appendChild(svgEl(
        `<circle cx="${x(i)}" cy="${y(s.count)}" r="3"
           fill="${SEV_COLORS[s.max_severity]}" stroke="#0b1220" stroke-width="1"/>`));
    }
  });
  el.appendChild(svg);
}

function chartSeverity(bySeverity) {
  const el = $("chartSeverity");
  el.innerHTML = "";
  const order = [4, 3, 2, 1];
  const total = order.reduce((sum, s) => sum + (bySeverity[s] || 0), 0);
  if (!total) { el.textContent = "no data"; return; }

  const W = 230, H = 190, cx = 78, cy = 95, r = 62, stroke = 20;
  const svg = svgEl(`<svg viewBox="0 0 ${W} ${H}"></svg>`);
  let angle = -Math.PI / 2;
  for (const sev of order) {
    const value = bySeverity[sev] || 0;
    if (!value) continue;
    const frac = value / total;
    const next = angle + frac * Math.PI * 2;
    const large = frac > 0.5 ? 1 : 0;
    const x1 = cx + r * Math.cos(angle), y1 = cy + r * Math.sin(angle);
    const x2 = cx + r * Math.cos(next), y2 = cy + r * Math.sin(next);
    svg.appendChild(svgEl(
      `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}"
         fill="none" stroke="${SEV_COLORS[sev]}" stroke-width="${stroke}"
         stroke-linecap="butt"/>`));
    angle = next;
  }
  svg.appendChild(svgEl(
    `<text x="${cx}" y="${cy - 2}" fill="#dbe4f3" font-size="24" font-weight="700"
       text-anchor="middle">${total}</text>`));
  svg.appendChild(svgEl(
    `<text x="${cx}" y="${cy + 16}" fill="#7c8aa5" font-size="9" text-anchor="middle">ALERTS</text>`));
  // legend
  let ly = cy - 46;
  for (const sev of order) {
    const value = bySeverity[sev] || 0;
    if (!value) continue;
    svg.appendChild(svgEl(
      `<rect x="${cx + 44}" y="${ly - 7}" width="9" height="9" rx="2" fill="${SEV_COLORS[sev]}"/>`));
    svg.appendChild(svgEl(
      `<text x="${cx + 58}" y="${ly + 1}" fill="#dbe4f3" font-size="10">
         ${SEV_NAMES[sev]} (${value})</text>`));
    ly += 17;
  }
  el.appendChild(svg);
}

function chartBars(items, mountId, color, valueSuffix) {
  const el = $(mountId);
  el.innerHTML = "";
  if (!items.length) { el.textContent = "no data"; return; }
  const W = 300, rowH = 30, PAD_L = 118;
  const H = Math.max(190, items.length * rowH + 12);
  const max = Math.max(1, ...items.map((i) => i.value));
  const svg = svgEl(`<svg viewBox="0 0 ${W} ${H}"></svg>`);
  items.forEach((item, i) => {
    const yy = i * rowH + 10;
    const barW = Math.max(3, ((W - PAD_L - 12) * item.value) / max);
    svg.appendChild(svgEl(
      `<text x="${PAD_L - 8}" y="${yy + 11}" fill="#dbe4f3" font-size="10.5"
         text-anchor="end">${escapeHtml(String(item.label).slice(0, 20))}</text>`));
    svg.appendChild(svgEl(
      `<rect x="${PAD_L}" y="${yy}" width="${barW}" height="15" rx="4"
         fill="${color}" opacity="0.85"/>`));
    svg.appendChild(svgEl(
      `<text x="${PAD_L + barW + 5}" y="${yy + 11}" fill="#7c8aa5" font-size="10">
         ${item.value}${valueSuffix || ""}</text>`));
  });
  el.appendChild(svg);
}

/* ============================ rendering ============================ */

function renderEngine(status) {
  const dot = $("engineDot"), text = $("engineText");
  if (status.running) {
    dot.className = "dot live";
    text.textContent = `engine live - ${status.info || "monitoring"}`;
  } else {
    dot.className = "dot dead";
    text.textContent = "engine stopped - showing stored alerts";
  }
}

function renderAlerts(payload) {
  const tbody = $("alertRows");
  const alerts = payload.alerts;
  $("alertCount").textContent =
    `showing ${alerts.length} alert(s) - newest first`;
  if (!alerts.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">no alerts match the filters</td></tr>`;
    return;
  }
  tbody.innerHTML = alerts.map((a) => `
    <tr>
      <td class="mono">${escapeHtml(a.time)}</td>
      <td><span class="badge s${a.severity}">${a.severity}</span></td>
      <td><span class="badge cat">${escapeHtml(a.category)}</span></td>
      <td>${escapeHtml(a.name)}
          <div class="muted small" style="margin:2px 0 0">${escapeHtml(a.details || "")}</div></td>
      <td class="mono">${escapeHtml(a.src_ip || "-")}${a.src_port ? ":" + a.src_port : ""}</td>
      <td class="mono">${escapeHtml(a.dst_ip || "-")}${a.dst_port ? ":" + a.dst_port : ""}</td>
      <td><span class="badge action-${a.action === "blocked" ? "blocked" : "logged"}">
        ${a.action === "blocked" ? "BLOCKED" : "logged"}</span></td>
    </tr>`).join("");
}

function renderBlocks(payload) {
  const el = $("blockedList");
  $("kpiBlocked").textContent = payload.count;
  if (!payload.blocks.length) {
    el.innerHTML = `<p class="muted">No active blocks.</p>`;
  } else {
    el.innerHTML = payload.blocks.map((b) => `
      <div class="blocked-item">
        <div>
          <div class="ip mono">${escapeHtml(b.ip)}</div>
          <div class="meta">${escapeHtml(b.mode)} &middot; until ${escapeHtml(b.expires)}</div>
          <div class="meta">${escapeHtml(b.reason || "")}</div>
        </div>
        <button class="unblock" data-ip="${escapeHtml(b.ip)}">unblock</button>
      </div>`).join("");
    el.querySelectorAll(".unblock").forEach((btn) =>
      btn.addEventListener("click", () => unblockIp(btn.dataset.ip)));
  }
}

function populateCategories(byCategory) {
  const select = $("filterCategory");
  const current = select.value;
  const names = byCategory.map((c) => c.category);
  if (JSON.stringify(names) === JSON.stringify(state.categories)) return;
  state.categories = names;
  select.innerHTML = `<option value="">All categories</option>` +
    names.map((n) => `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`).join("");
  select.value = current;
}

async function refresh() {
  try {
    const [stats, series, alerts, blocks] = await Promise.all([
      fetchJson("/api/stats"),
      fetchJson("/api/timeseries?minutes=60"),
      fetchJson(`/api/alerts?limit=120&severity=${$("filterSeverity").value}` +
        `&category=${encodeURIComponent($("filterCategory").value)}` +
        `&q=${encodeURIComponent($("filterSearch").value)}`),
      fetchJson("/api/blocked"),
    ]);
    $("kpiTotal").textContent = stats.total_alerts.toLocaleString();
    $("kpiCritical").textContent = stats.by_severity[4] || 0;
    $("kpiHigh").textContent = stats.by_severity[3] || 0;
    $("kpiSources").textContent = stats.unique_sources;
    $("dbPath").textContent = stats.db_path;
    renderEngine(stats.engine);
    chartTimeline(series.series);
    chartSeverity(stats.by_severity);
    chartBars(stats.by_category.slice(0, 8).map((c) => ({ label: c.category, value: c.count })),
              "chartCategories", "#38bdf8");
    chartBars(stats.top_sources.slice(0, 8).map((s) => ({ label: s.ip, value: s.count })),
              "chartSources", "#f43f5e");
    populateCategories(stats.by_category);
    renderAlerts(alerts);
    renderBlocks(blocks);
  } catch (error) {
    console.error(error);
    $("engineDot").className = "dot dead";
    $("engineText").textContent = "dashboard API unreachable";
  }
}

/* ============================ actions ============================ */

async function blockIp(event) {
  event.preventDefault();
  const ip = $("blockIp").value.trim();
  if (!ip) return;
  try {
    const result = await fetchJson("/api/block", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, reason: "manual block from dashboard" }),
    });
    showToast(result.message);
    $("blockIp").value = "";
    refresh();
  } catch (error) {
    showToast("block failed: " + error.message);
  }
}

async function unblockIp(ip) {
  try {
    const result = await fetchJson("/api/unblock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    showToast(result.message);
    refresh();
  } catch (error) {
    showToast("unblock failed: " + error.message);
  }
}

/* ============================ boot ============================ */

function setAutoRefresh(enabled) {
  if (state.timer) clearInterval(state.timer);
  const intervalMs = (window.NIDS_REFRESH_SECONDS || 5) * 1000;
  state.timer = enabled ? setInterval(refresh, intervalMs) : null;
}

document.addEventListener("DOMContentLoaded", () => {
  $("blockForm").addEventListener("submit", blockIp);
  $("btnRefresh").addEventListener("click", refresh);
  $("btnExport").addEventListener("click",
    () => { window.location.href = "/api/export/csv"; });
  $("autoRefresh").addEventListener("change", (e) => setAutoRefresh(e.target.checked));
  $("filterSeverity").addEventListener("change", refresh);
  $("filterCategory").addEventListener("change", refresh);
  $("filterSearch").addEventListener("keydown", (e) => {
    if (e.key === "Enter") refresh();
  });
  setAutoRefresh(true);
  refresh();
});
