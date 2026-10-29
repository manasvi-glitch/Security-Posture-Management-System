// ============================================================
// API client
// ============================================================
const API_BASE = (() => {
  // If served from the backend's own static mount (recommended), same
  // origin works. If opened separately (e.g. `python -m http.server`
  // inside /frontend), fall back to localhost:8420.
  if (location.protocol === "file:" || (location.port && location.port !== "8420" && location.port !== "")) {
    return "http://localhost:8420";
  }
  return "";
})();

const state = {
  token: localStorage.getItem("spp_token") || null,
  user: null,
  route: "dashboard",
  usersCache: null,
};

async function api(path, { method = "GET", body, isForm = false } = {}) {
  const headers = {};
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  if (body && !isForm) headers["Content-Type"] = "application/json";

  const resp = await fetch(API_BASE + path, {
    method,
    headers,
    body: body ? (isForm ? body : JSON.stringify(body)) : undefined,
  });

  if (resp.status === 401) {
    logout();
    throw new Error("Session expired. Please sign in again.");
  }
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).detail || detail; } catch (e) {}
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (resp.status === 204) return null;
  const ct = resp.headers.get("content-type") || "";
  return ct.includes("application/json") ? resp.json() : resp.text();
}

// ============================================================
// Auth
// ============================================================
function logout() {
  state.token = null;
  state.user = null;
  localStorage.removeItem("spp_token");
  document.getElementById("app").style.display = "none";
  document.getElementById("loginScreen").style.display = "flex";
}

async function login(username, password) {
  const form = new URLSearchParams();
  form.set("username", username);
  form.set("password", password);
  const resp = await fetch(API_BASE + "/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.detail || "Login failed");
  }
  const data = await resp.json();
  state.token = data.access_token;
  state.user = data.user;
  localStorage.setItem("spp_token", state.token);
  onAuthenticated();
}

async function tryResumeSession() {
  if (!state.token) return false;
  try {
    state.user = await api("/api/auth/me");
    return true;
  } catch (e) {
    return false;
  }
}

function onAuthenticated() {
  document.getElementById("loginScreen").style.display = "none";
  document.getElementById("app").style.display = "grid";
  document.getElementById("roleBadge").textContent = state.user.role.toUpperCase();
  document.getElementById("avatarBtn").textContent = state.user.username.slice(0, 2).toUpperCase();
  document.getElementById("adminNavItem").style.display = state.user.role === "admin" ? "flex" : "none";
  navigate(location.hash.replace("#/", "") || "dashboard");
}

// ============================================================
// Router
// ============================================================
const routes = {
  dashboard: renderDashboard,
  assets: renderAssets,
  findings: renderFindings,
  reports: renderReports,
  admin: renderAdmin,
};

function navigate(route) {
  if (!routes[route]) route = "dashboard";
  if (route === "admin" && (!state.user || state.user.role !== "admin")) route = "dashboard";
  state.route = route;
  location.hash = "#/" + route;
  document.querySelectorAll(".rail-item").forEach(el => {
    el.classList.toggle("active", el.dataset.route === route);
  });
  routes[route]();
}

document.querySelectorAll(".rail-item[data-route]").forEach(el => {
  el.addEventListener("click", () => navigate(el.dataset.route));
});

// ============================================================
// Helpers
// ============================================================
const CATEGORY_LABEL = {
  authentication: "Authentication", network: "Network Security", configuration: "Configuration",
  patch_management: "Patch Management", access_control: "Access Control", application: "Application Security",
};
const STATUS_LABEL = {
  detected: "Detected", triaged: "Triaged", assigned: "Assigned", fix_in_progress: "Fix in progress",
  remediated: "Remediated", verification: "Verification", resolved: "Resolved", reopened: "Reopened",
};
const NEXT_STATUS = {
  detected: ["triaged"], triaged: ["assigned"], assigned: ["fix_in_progress"],
  fix_in_progress: ["remediated"], remediated: ["verification"], verification: ["resolved", "reopened"],
  resolved: ["reopened"], reopened: ["triaged"],
};
function sevClass(sev) { return "sev-" + sev; }
function scoreColor(score) {
  if (score >= 80) return "var(--good)";
  if (score >= 60) return "var(--medium)";
  if (score >= 40) return "var(--high)";
  return "var(--critical)";
}
function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}
function canEdit() { return state.user && (state.user.role === "admin" || state.user.role === "analyst"); }
function isAdmin() { return state.user && state.user.role === "admin"; }

function toast(msg, isError = false) {
  const host = document.getElementById("toastHost");
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function openModal(html) {
  document.getElementById("modalBody").innerHTML = html;
  document.getElementById("modalBackdrop").classList.add("open");
}
function closeModal() {
  document.getElementById("modalBackdrop").classList.remove("open");
  document.getElementById("modalBody").innerHTML = "";
}
document.getElementById("modalBackdrop").addEventListener("click", (e) => {
  if (e.target.id === "modalBackdrop") closeModal();
});

async function ensureUsersCache() {
  if (!state.usersCache) state.usersCache = await api("/api/users");
  return state.usersCache;
}

const main = () => document.getElementById("mainContent");

// ============================================================
// DASHBOARD
// ============================================================
async function renderDashboard() {
  main().innerHTML = `<div class="page-head"><div><h1>Overview</h1><div class="sub">Live posture computed from open findings</div></div></div>
    <div id="dashBody" class="grid"><div class="panel" style="grid-column:span 12; text-align:center; color:var(--text-dim); padding:40px;">Loading…</div></div>`;

  let d;
  try {
    d = await api("/api/dashboard/summary");
  } catch (e) {
    main().querySelector("#dashBody").innerHTML = `<div class="panel" style="grid-column:span 12;">${e.message}</div>`;
    return;
  }

  const catColors = { authentication: "var(--good)", network: "var(--medium)", configuration: "var(--good)",
    patch_management: "var(--high)", access_control: "var(--good)", application: "var(--good)" };
  const catRows = d.posture.categories.map(c => `
    <div class="cat-row">
      <span class="cat-name">${CATEGORY_LABEL[c.category]}</span>
      <div class="cat-bar"><div class="cat-bar-fill" data-w="${c.score}" style="background:${scoreColor(c.score)}"></div></div>
      <span class="cat-score">${c.score}</span>
    </div>`).join("");

  const trendDir = d.posture.trend_30d >= 0 ? "up" : "down";
  const trendSign = d.posture.trend_30d >= 0 ? "▲" : "▼";

  const priorityRows = d.top_priorities.length ? d.top_priorities.map(p => `
    <div class="pr-row">
      <span class="pr-rank">${String(p.rank).padStart(2, "0")}</span>
      <span class="sev-tag ${sevClass(p.severity)}">${p.severity.toUpperCase()}</span>
      <span class="pr-title" title="${escapeHtml(p.title)}">${escapeHtml(p.title)}</span>
      <span class="pr-asset">${escapeHtml(p.asset_name)}</span>
      <span class="pr-action" data-open-finding="${p.finding_id}">View</span>
    </div>`).join("") : `<div class="empty-state">No open findings — posture is clean.</div>`;

  const pipeStages = [
    ["Detected", d.pipeline.detected, "var(--text-dim)"],
    ["Triaged", d.pipeline.triaged, "var(--low)"],
    ["Assigned", d.pipeline.assigned, "var(--low)"],
    ["Fix in<br>progress", d.pipeline.fix_in_progress, "var(--medium)"],
    ["Remediated", d.pipeline.remediated, "var(--accent)"],
    ["Verification", d.pipeline.verification, "var(--accent)"],
    ["Resolved<br>(30d)", d.pipeline.resolved_30d, "var(--good)"],
  ];
  const maxPipe = Math.max(1, ...pipeStages.map(s => s[1]));
  const pipeHtml = pipeStages.map(([label, count, color]) => `
    <div class="pipe-stage"><span class="pipe-count">${count}</span>
      <div class="pipe-bar" data-h="${Math.round((count / maxPipe) * 100)}" style="background:${color}"></div>
      <span class="pipe-label">${label}</span></div>`).join("");

  const trendMax = Math.max(...d.trend.map(t => t.score), 1);
  const trendMin = Math.min(...d.trend.map(t => t.score), 0);
  const range = Math.max(trendMax - trendMin, 1);
  const pts = d.trend.map((t, i) => {
    const x = (i / (d.trend.length - 1)) * 300;
    const y = 100 - ((t.score - trendMin) / range) * 90;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");

  main().querySelector("#dashBody").innerHTML = `
    <div class="panel hero">
      <div class="panel-title">Security Posture Score</div>
      <div class="hero-body">
        <div class="gauge-wrap">
          <svg width="150" height="150" viewBox="0 0 150 150">
            <circle cx="75" cy="75" r="63" fill="none" stroke="#1A212B" stroke-width="10"/>
            <circle id="gaugeArc" cx="75" cy="75" r="63" fill="none" stroke="${scoreColor(d.posture.overall)}" stroke-width="10"
              stroke-linecap="round" stroke-dasharray="396" stroke-dashoffset="396" transform="rotate(-90 75 75)"/>
          </svg>
          <div class="gauge-num"><div class="n">${Math.round(d.posture.overall)}</div><div class="d">/ 100</div></div>
        </div>
        <div class="hero-side">
          <div class="rating" style="color:${scoreColor(d.posture.overall)}">${d.posture.rating}</div>
          <div class="trend-line"><span class="${trendDir}">${trendSign} ${Math.abs(d.posture.trend_30d)} pts</span> vs. previous 30 days</div>
          <div class="cat-list">${catRows}</div>
        </div>
      </div>
    </div>

    <div class="strip">
      <div class="stat-panel">
        <div class="stat-head">Findings (open)</div>
        <div class="stat-rows">
          <div class="stat-row"><span class="stat-label"><span class="dot" style="background:var(--critical)"></span>Critical</span><span class="stat-val">${d.findings.critical}</span></div>
          <div class="stat-row"><span class="stat-label"><span class="dot" style="background:var(--high)"></span>High</span><span class="stat-val">${d.findings.high}</span></div>
          <div class="stat-row"><span class="stat-label"><span class="dot" style="background:var(--medium)"></span>Medium</span><span class="stat-val">${d.findings.medium}</span></div>
          <div class="stat-row"><span class="stat-label"><span class="dot" style="background:var(--low)"></span>Low</span><span class="stat-val">${d.findings.low}</span></div>
        </div>
        <div class="stat-total"><span>Total open</span><b>${d.findings.total}</b></div>
      </div>
      <div class="stat-panel">
        <div class="stat-head">Assets</div>
        <div class="stat-rows">
          <div class="stat-row"><span class="stat-label">Total assets</span><span class="stat-val">${d.assets.total}</span></div>
          <div class="stat-row"><span class="stat-label">High-risk</span><span class="stat-val" style="color:var(--high)">${d.assets.high_risk}</span></div>
          <div class="stat-row"><span class="stat-label">Internet-facing</span><span class="stat-val" style="color:var(--medium)">${d.assets.internet_facing}</span></div>
          <div class="stat-row"><span class="stat-label">Needs attention</span><span class="stat-val">${d.assets.needs_attention}</span></div>
        </div>
        <div class="stat-total"><span>Coverage</span><b>100%</b></div>
      </div>
      <div class="stat-panel">
        <div class="stat-head">Remediation</div>
        <div class="stat-rows">
          <div class="stat-row"><span class="stat-label">Open</span><span class="stat-val">${d.remediation.open}</span></div>
          <div class="stat-row"><span class="stat-label">In progress</span><span class="stat-val" style="color:var(--accent)">${d.remediation.in_progress}</span></div>
          <div class="stat-row"><span class="stat-label">Resolved (30d)</span><span class="stat-val" style="color:var(--good)">${d.remediation.resolved_30d}</span></div>
        </div>
        <div class="stat-total"><span>Avg. time to fix</span><b>${d.remediation.avg_days_to_fix ?? "—"}${d.remediation.avg_days_to_fix ? "d" : ""}</b></div>
      </div>
    </div>

    <div class="panel priorities">
      <div class="panel-title">Top Security Priorities <span class="hint">Ranked by computed risk score</span></div>
      <div>${priorityRows}</div>
    </div>

    <div class="panel pipeline">
      <div class="panel-title">Remediation Pipeline <span class="hint">Findings by stage</span></div>
      <div class="pipe-stages">${pipeHtml}</div>
    </div>

    <div class="panel trend">
      <div class="panel-title">Posture Trend <span class="hint">Approximate, last ~6 months</span></div>
      <svg width="100%" height="110" viewBox="0 0 300 110" preserveAspectRatio="none">
        <polyline fill="none" stroke="#4FA8E0" stroke-width="2" points="${pts}"/>
      </svg>
      <div class="trend-legend">${d.trend.map(t => `<span>${t.label}</span>`).join("")}</div>
    </div>
  `;

  requestAnimationFrame(() => {
    const arc = document.getElementById("gaugeArc");
    const circumference = 396;
    arc.style.transition = "stroke-dashoffset 1.1s cubic-bezier(.2,.8,.2,1)";
    arc.style.strokeDashoffset = String(circumference - (d.posture.overall / 100) * circumference);
    document.querySelectorAll(".cat-bar-fill").forEach((el, i) => {
      setTimeout(() => { el.style.width = el.dataset.w + "%"; }, 120 + i * 60);
    });
    document.querySelectorAll(".pipe-bar").forEach((el, i) => {
      setTimeout(() => { el.style.height = el.dataset.h + "%"; }, 150 + i * 70);
    });
  });

  main().querySelectorAll("[data-open-finding]").forEach(el => {
    el.addEventListener("click", () => openFindingDetail(el.dataset.openFinding));
  });
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ============================================================
// ASSETS
// ============================================================
async function renderAssets() {
  main().innerHTML = `
    <div class="page-head">
      <div><h1>Asset Inventory</h1><div class="sub">Servers, applications, and network devices in scope</div></div>
      ${canEdit() ? `<button class="btn" id="newAssetBtn">+ New asset</button>` : ""}
    </div>
    <div class="panel" id="assetsPanel"><div class="empty-state">Loading…</div></div>
  `;
  if (canEdit()) document.getElementById("newAssetBtn").addEventListener("click", openAssetForm);

  let assets;
  try { assets = await api("/api/assets"); }
  catch (e) { document.getElementById("assetsPanel").innerHTML = `<div class="empty-state">${e.message}</div>`; return; }

  if (!assets.length) {
    document.getElementById("assetsPanel").innerHTML = `<div class="empty-state">No assets yet. Add one, or import a scan from Reports & Import.</div>`;
    return;
  }

  const rows = assets.map(a => `
    <tr>
      <td>${escapeHtml(a.name)}</td>
      <td style="text-transform:capitalize">${a.asset_type.replace("_", " ")}</td>
      <td style="text-transform:capitalize">${a.criticality}</td>
      <td>${a.internet_facing ? "Yes" : "No"}</td>
      <td>${a.ip_address ? escapeHtml(a.ip_address) : "—"}</td>
      <td><span class="risk-val" style="color:${a.open_finding_count > 0 ? "var(--high)" : "var(--good)"}">${a.open_finding_count}</span></td>
      <td>${isAdmin() ? `<button class="btn ghost small" data-delete-asset="${a.id}">Delete</button>` : ""}</td>
    </tr>`).join("");

  document.getElementById("assetsPanel").innerHTML = `
    <table><thead><tr>
      <th>Name</th><th>Type</th><th>Criticality</th><th>Internet-facing</th><th>IP address</th><th>Open findings</th><th></th>
    </tr></thead><tbody>${rows}</tbody></table>`;

  document.querySelectorAll("[data-delete-asset]").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (!confirm("Delete this asset and all of its findings?")) return;
      try { await api(`/api/assets/${btn.dataset.deleteAsset}`, { method: "DELETE" }); toast("Asset deleted"); renderAssets(); }
      catch (e) { toast(e.message, true); }
    });
  });
}

function openAssetForm() {
  openModal(`
    <h3>New asset</h3>
    <div class="field"><label>Name</label><input id="af_name" required></div>
    <div class="field"><label>Type</label><select id="af_type">
      <option value="server">Server</option><option value="workstation">Workstation</option>
      <option value="network_device">Network device</option><option value="application">Application</option>
      <option value="cloud_resource">Cloud resource</option></select></div>
    <div class="field"><label>Criticality</label><select id="af_crit">
      <option value="low">Low</option><option value="medium" selected>Medium</option>
      <option value="high">High</option><option value="critical">Critical</option></select></div>
    <div class="field"><label>IP address (optional)</label><input id="af_ip"></div>
    <div class="field"><label>Owner (optional)</label><input id="af_owner"></div>
    <div class="field" style="display:flex; align-items:center; gap:8px;">
      <input type="checkbox" id="af_internet" style="width:auto;"><label style="margin:0" for="af_internet">Internet-facing</label>
    </div>
    <div class="modal-actions">
      <button class="btn ghost" id="af_cancel">Cancel</button>
      <button class="btn" id="af_save">Create asset</button>
    </div>
  `);
  document.getElementById("af_cancel").addEventListener("click", closeModal);
  document.getElementById("af_save").addEventListener("click", async () => {
    const name = document.getElementById("af_name").value.trim();
    if (!name) { toast("Name is required", true); return; }
    try {
      await api("/api/assets", { method: "POST", body: {
        name, asset_type: document.getElementById("af_type").value,
        criticality: document.getElementById("af_crit").value,
        ip_address: document.getElementById("af_ip").value || null,
        owner: document.getElementById("af_owner").value || null,
        internet_facing: document.getElementById("af_internet").checked,
      }});
      toast("Asset created"); closeModal(); renderAssets();
    } catch (e) { toast(e.message, true); }
  });
}

// ============================================================
// FINDINGS
// ============================================================
let findingsFilters = { severity: "", category: "", status: "" };

async function renderFindings() {
  main().innerHTML = `
    <div class="page-head">
      <div><h1>Findings</h1><div class="sub">All findings across the asset inventory, ranked by risk score</div></div>
      ${canEdit() ? `<button class="btn" id="newFindingBtn">+ New finding</button>` : ""}
    </div>
    <div class="toolbar">
      <select id="f_severity"><option value="">All severities</option>
        <option value="critical">Critical</option><option value="high">High</option>
        <option value="medium">Medium</option><option value="low">Low</option></select>
      <select id="f_category"><option value="">All categories</option>
        ${Object.entries(CATEGORY_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
      <select id="f_status"><option value="">All statuses</option>
        ${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select>
    </div>
    <div class="panel" id="findingsPanel"><div class="empty-state">Loading…</div></div>
  `;
  document.getElementById("f_severity").value = findingsFilters.severity;
  document.getElementById("f_category").value = findingsFilters.category;
  document.getElementById("f_status").value = findingsFilters.status;
  ["severity", "category", "status"].forEach(k => {
    document.getElementById("f_" + k).addEventListener("change", (e) => {
      findingsFilters[k] = e.target.value;
      loadFindingsTable();
    });
  });
  if (canEdit()) document.getElementById("newFindingBtn").addEventListener("click", openFindingForm);

  await loadFindingsTable();
}

async function loadFindingsTable() {
  const panel = document.getElementById("findingsPanel");
  panel.innerHTML = `<div class="empty-state">Loading…</div>`;
  const params = new URLSearchParams();
  Object.entries(findingsFilters).forEach(([k, v]) => { if (v) params.set(k, v); });
  let findings;
  try { findings = await api("/api/findings?" + params.toString()); }
  catch (e) { panel.innerHTML = `<div class="empty-state">${e.message}</div>`; return; }

  if (!findings.length) {
    panel.innerHTML = `<div class="empty-state">No findings match these filters.</div>`;
    return;
  }

  const rows = findings.map(f => `
    <tr>
      <td><span class="sev-tag ${sevClass(f.severity)}">${f.severity.toUpperCase()}</span></td>
      <td style="max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(f.title)}">${escapeHtml(f.title)}</td>
      <td>${CATEGORY_LABEL[f.category]}</td>
      <td class="risk-val" style="color:${scoreColor(100 - f.risk_score)}">${f.risk_score}</td>
      <td><span class="status-pill status-${f.status}">${STATUS_LABEL[f.status]}</span></td>
      <td>${fmtDate(f.created_at)}</td>
      <td><button class="btn ghost small" data-open-finding="${f.id}">Open</button></td>
    </tr>`).join("");

  panel.innerHTML = `<table><thead><tr>
      <th>Severity</th><th>Title</th><th>Category</th><th>Risk score</th><th>Status</th><th>Detected</th><th></th>
    </tr></thead><tbody>${rows}</tbody></table>`;

  panel.querySelectorAll("[data-open-finding]").forEach(btn => {
    btn.addEventListener("click", () => openFindingDetail(btn.dataset.openFinding));
  });
}

async function openFindingForm() {
  let assets;
  try { assets = await api("/api/assets"); } catch (e) { toast(e.message, true); return; }
  if (!assets.length) { toast("Create an asset first", true); return; }

  openModal(`
    <h3>New finding</h3>
    <div class="field"><label>Asset</label><select id="nf_asset">${assets.map(a => `<option value="${a.id}">${escapeHtml(a.name)}</option>`).join("")}</select></div>
    <div class="field"><label>Title</label><input id="nf_title" required></div>
    <div class="field"><label>Description</label><textarea id="nf_desc"></textarea></div>
    <div class="field"><label>Severity</label><select id="nf_sev">
      <option value="critical">Critical</option><option value="high" selected>High</option>
      <option value="medium">Medium</option><option value="low">Low</option></select></div>
    <div class="field"><label>Category</label><select id="nf_cat">
      ${Object.entries(CATEGORY_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join("")}</select></div>
    <div class="field"><label>Exploitability</label><select id="nf_expl">
      <option value="theoretical">Theoretical</option><option value="poc" selected>Proof-of-concept exists</option>
      <option value="active">Actively exploited</option></select></div>
    <div class="field"><label>CVE ID (optional)</label><input id="nf_cve" placeholder="CVE-2024-XXXXX"></div>
    <div class="modal-actions">
      <button class="btn ghost" id="nf_cancel">Cancel</button>
      <button class="btn" id="nf_save">Create finding</button>
    </div>
  `);
  document.getElementById("nf_cancel").addEventListener("click", closeModal);
  document.getElementById("nf_save").addEventListener("click", async () => {
    const title = document.getElementById("nf_title").value.trim();
    if (!title) { toast("Title is required", true); return; }
    try {
      await api("/api/findings", { method: "POST", body: {
        asset_id: document.getElementById("nf_asset").value, title,
        description: document.getElementById("nf_desc").value || null,
        severity: document.getElementById("nf_sev").value,
        category: document.getElementById("nf_cat").value,
        exploitability: document.getElementById("nf_expl").value,
        cve_id: document.getElementById("nf_cve").value || null,
      }});
      toast("Finding created"); closeModal(); loadFindingsTable();
    } catch (e) { toast(e.message, true); }
  });
}

async function openFindingDetail(findingId) {
  let f;
  try { f = await api(`/api/findings/${findingId}`); } catch (e) { toast(e.message, true); return; }

  const nextStatuses = NEXT_STATUS[f.status] || [];
  const statusOptions = nextStatuses.map(s => `<option value="${s}">${STATUS_LABEL[s]}</option>`).join("");

  const users = canEdit() ? await ensureUsersCache() : [];
  const userOptions = users.map(u => `<option value="${u.id}" ${u.id === f.assigned_to ? "selected" : ""}>${u.username} (${u.role})</option>`).join("");

  const eventsHtml = (f.events || []).slice().reverse().map(ev => `
    <div class="event-item">
      <div>${eventLabel(ev)}</div>
      <div class="event-meta">${fmtDate(ev.created_at)} · ${ev.action}</div>
    </div>`).join("") || `<div class="event-meta">No activity yet.</div>`;

  openModal(`
    <h3>${escapeHtml(f.title)}</h3>
    <div style="display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap;">
      <span class="sev-tag ${sevClass(f.severity)}">${f.severity.toUpperCase()}</span>
      <span class="status-pill status-${f.status}">${STATUS_LABEL[f.status]}</span>
      <span class="status-pill">Risk score: ${f.risk_score}</span>
    </div>
    ${f.description ? `<p style="color:var(--text-muted); font-size:12.5px; margin-bottom:14px;">${escapeHtml(f.description)}</p>` : ""}
    <p style="color:var(--text-dim); font-size:11.5px; margin-bottom:14px;">
      Category: ${CATEGORY_LABEL[f.category]} · Exploitability: ${f.exploitability}${f.cve_id ? " · " + escapeHtml(f.cve_id) : ""}
    </p>

    ${canEdit() ? `
    <div class="field">
      <label>Move to next status</label>
      <div style="display:flex; gap:8px;">
        <select id="fd_status" ${!nextStatuses.length ? "disabled" : ""} style="flex:1; background:var(--bg); border:1px solid var(--border); border-radius:5px; padding:9px;">
          ${statusOptions || "<option>No further transitions</option>"}
        </select>
        <button class="btn small" id="fd_status_go" ${!nextStatuses.length ? "disabled" : ""}>Update</button>
      </div>
    </div>
    <div class="field">
      <label>Assign to</label>
      <div style="display:flex; gap:8px;">
        <select id="fd_assignee" style="flex:1; background:var(--bg); border:1px solid var(--border); border-radius:5px; padding:9px;">
          <option value="">— Unassigned —</option>${userOptions}
        </select>
        <button class="btn small ghost" id="fd_assign_go">Assign</button>
      </div>
    </div>
    <div class="field">
      <label>Add note</label>
      <div style="display:flex; gap:8px;">
        <input id="fd_note" placeholder="e.g. Confirmed with vendor, patch scheduled for Friday" style="flex:1;">
        <button class="btn small ghost" id="fd_note_go">Add</button>
      </div>
    </div>
    ` : ""}

    <div class="event-log">
      <div class="panel-title" style="margin-bottom:10px;">Activity</div>
      ${eventsHtml}
    </div>

    <div class="modal-actions"><button class="btn ghost" id="fd_close">Close</button></div>
  `);

  document.getElementById("fd_close").addEventListener("click", closeModal);

  if (canEdit()) {
    const statusGo = document.getElementById("fd_status_go");
    if (statusGo) statusGo.addEventListener("click", async () => {
      try {
        await api(`/api/findings/${f.id}/status`, { method: "POST", body: { to_status: document.getElementById("fd_status").value } });
        toast("Status updated"); closeModal(); refreshCurrentView();
      } catch (e) { toast(e.message, true); }
    });
    document.getElementById("fd_assign_go").addEventListener("click", async () => {
      const userId = document.getElementById("fd_assignee").value;
      if (!userId) { toast("Select someone to assign", true); return; }
      try {
        await api(`/api/findings/${f.id}/assign`, { method: "POST", body: { user_id: userId } });
        toast("Assigned"); closeModal(); refreshCurrentView();
      } catch (e) { toast(e.message, true); }
    });
    document.getElementById("fd_note_go").addEventListener("click", async () => {
      const note = document.getElementById("fd_note").value.trim();
      if (!note) return;
      try {
        await api(`/api/findings/${f.id}/notes`, { method: "POST", body: { note } });
        toast("Note added"); closeModal(); openFindingDetail(f.id);
      } catch (e) { toast(e.message, true); }
    });
  }
}

function eventLabel(ev) {
  if (ev.action === "status_change") {
    if (!ev.from_status) return `Finding created (status: ${STATUS_LABEL[ev.to_status] || ev.to_status})`;
    return `Status changed: ${STATUS_LABEL[ev.from_status] || ev.from_status} → ${STATUS_LABEL[ev.to_status] || ev.to_status}${ev.note ? " — " + escapeHtml(ev.note) : ""}`;
  }
  if (ev.action === "assignment") return escapeHtml(ev.note || "Assigned");
  if (ev.action === "note") return escapeHtml(ev.note || "");
  if (ev.action === "evidence") return `Evidence attached: ${escapeHtml(ev.evidence_url || "")}${ev.note ? " — " + escapeHtml(ev.note) : ""}`;
  return escapeHtml(ev.action);
}

function refreshCurrentView() {
  if (routes[state.route]) routes[state.route]();
}

// ============================================================
// REPORTS & IMPORT
// ============================================================
function renderReports() {
  main().innerHTML = `
    <div class="page-head"><div><h1>Reports & Import</h1><div class="sub">Export the findings register, or ingest scan data from external tools</div></div></div>
    <div class="grid">
      <div class="panel" style="grid-column:span 12;">
        <div class="panel-title">Export</div>
        <p style="color:var(--text-muted); font-size:12.5px; margin-bottom:14px;">Download the full findings register as CSV, including risk scores, status, and assignment.</p>
        <button class="btn" id="exportCsvBtn">Download findings.csv</button>
      </div>

      ${canEdit() ? `
      <div class="panel" style="grid-column:span 6;">
        <div class="panel-title">Import — generic scan format (JSON)</div>
        <p style="color:var(--text-muted); font-size:12.5px; margin-bottom:10px;">
          Paste a list of findings in the <code>kestrel_scan</code> format (host, ip, finding, severity, description, cve).
          New assets are created automatically by hostname.
        </p>
        <textarea id="importJson" style="width:100%; min-height:160px; background:var(--bg); border:1px solid var(--border); border-radius:5px; padding:10px; font-family:var(--mono); font-size:11.5px; color:var(--text);" placeholder='[{"host":"web-edge-05","ip":"10.1.2.3","internet_facing":true,"finding":"Outdated TLS library","severity":"high","description":"..."}]'></textarea>
        <div style="margin-top:10px;"><button class="btn" id="importJsonBtn">Import JSON</button></div>
        <div id="importJsonResult" style="margin-top:10px; font-size:12px; color:var(--text-muted);"></div>
      </div>

      <div class="panel" style="grid-column:span 6;">
        <div class="panel-title">Import — Nessus/OpenVAS CSV export</div>
        <p style="color:var(--text-muted); font-size:12.5px; margin-bottom:10px;">
          Upload a CSV export with columns like <code>Host, Name, Risk, Synopsis, CVE, Plugin ID</code>.
        </p>
        <input type="file" id="importCsvFile" accept=".csv">
        <div style="margin-top:10px;"><button class="btn" id="importCsvBtn">Import CSV</button></div>
        <div id="importCsvResult" style="margin-top:10px; font-size:12px; color:var(--text-muted);"></div>
      </div>
      ` : ""}
    </div>
  `;

  document.getElementById("exportCsvBtn").addEventListener("click", async () => {
    try {
      const resp = await fetch(API_BASE + "/api/reports/findings.csv", { headers: { Authorization: "Bearer " + state.token } });
      if (!resp.ok) throw new Error("Export failed");
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "findings_report.csv"; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { toast(e.message, true); }
  });

  if (canEdit()) {
    document.getElementById("importJsonBtn").addEventListener("click", async () => {
      const raw = document.getElementById("importJson").value.trim();
      const resultEl = document.getElementById("importJsonResult");
      if (!raw) { toast("Paste some JSON first", true); return; }
      let parsed;
      try { parsed = JSON.parse(raw); } catch (e) { toast("Invalid JSON", true); return; }
      try {
        const result = await api("/api/findings/import/kestrel-scan", { method: "POST", body: parsed });
        resultEl.textContent = `Created ${result.assets_created} asset(s) and ${result.findings_created} finding(s). Skipped ${result.findings_skipped} duplicate(s).` + (result.errors.length ? ` Errors: ${result.errors.join("; ")}` : "");
        toast("Import complete");
      } catch (e) { toast(e.message, true); }
    });

    document.getElementById("importCsvBtn").addEventListener("click", async () => {
      const fileInput = document.getElementById("importCsvFile");
      const resultEl = document.getElementById("importCsvResult");
      if (!fileInput.files.length) { toast("Choose a CSV file first", true); return; }
      const form = new FormData();
      form.append("file", fileInput.files[0]);
      try {
        const result = await api("/api/findings/import/nessus-csv", { method: "POST", body: form, isForm: true });
        resultEl.textContent = `Created ${result.assets_created} asset(s) and ${result.findings_created} finding(s). Skipped ${result.findings_skipped} duplicate(s).` + (result.errors.length ? ` Errors: ${result.errors.join("; ")}` : "");
        toast("Import complete");
      } catch (e) { toast(e.message, true); }
    });
  }
}

// ============================================================
// ADMIN (users + audit log)
// ============================================================
async function renderAdmin() {
  main().innerHTML = `
    <div class="page-head"><div><h1>Admin</h1><div class="sub">User roles and system audit trail</div></div></div>
    <div class="grid">
      <div class="panel" style="grid-column:span 5;">
        <div class="panel-title">Users</div>
        <div id="usersPanel"><div class="empty-state">Loading…</div></div>
      </div>
      <div class="panel" style="grid-column:span 7;">
        <div class="panel-title">Audit log <span class="hint">Most recent 50 actions</span></div>
        <div id="auditPanel"><div class="empty-state">Loading…</div></div>
      </div>
    </div>
  `;

  try {
    const users = await api("/api/users");
    state.usersCache = users;
    document.getElementById("usersPanel").innerHTML = `<table><thead><tr><th>Username</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr>
        <td>${escapeHtml(u.username)}</td>
        <td>
          <select data-role-select="${u.id}" ${u.id === state.user.id ? "disabled" : ""} style="background:var(--bg); border:1px solid var(--border); border-radius:4px; padding:4px 6px;">
            ${["admin", "analyst", "viewer"].map(r => `<option value="${r}" ${r === u.role ? "selected" : ""}>${r}</option>`).join("")}
          </select>
        </td>
        <td>${u.is_active ? "Active" : "Disabled"}</td>
        <td>${u.is_active && u.id !== state.user.id ? `<button class="btn ghost small" data-deactivate="${u.id}">Disable</button>` : ""}</td>
      </tr>`).join("")}
    </tbody></table>`;

    document.querySelectorAll("[data-role-select]").forEach(sel => {
      sel.addEventListener("change", async () => {
        try {
          await api(`/api/users/${sel.dataset.roleSelect}/role?role=${sel.value}`, { method: "PATCH" });
          toast("Role updated"); state.usersCache = null;
        } catch (e) { toast(e.message, true); }
      });
    });
    document.querySelectorAll("[data-deactivate]").forEach(btn => {
      btn.addEventListener("click", async () => {
        try {
          await api(`/api/users/${btn.dataset.deactivate}/deactivate`, { method: "PATCH" });
          toast("User disabled"); state.usersCache = null; renderAdmin();
        } catch (e) { toast(e.message, true); }
      });
    });
  } catch (e) { document.getElementById("usersPanel").innerHTML = `<div class="empty-state">${e.message}</div>`; }

  try {
    const logs = await api("/api/audit?limit=50");
    document.getElementById("auditPanel").innerHTML = logs.length ? `<table><thead><tr><th>When</th><th>User</th><th>Action</th><th>Detail</th></tr></thead><tbody>
      ${logs.map(l => `<tr>
        <td style="white-space:nowrap;">${new Date(l.created_at).toLocaleString()}</td>
        <td>${escapeHtml(l.username || "—")}</td>
        <td>${escapeHtml(l.action)}</td>
        <td style="max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(l.detail || "")}">${escapeHtml(l.detail || "—")}</td>
      </tr>`).join("")}
    </tbody></table>` : `<div class="empty-state">No activity recorded yet.</div>`;
  } catch (e) { document.getElementById("auditPanel").innerHTML = `<div class="empty-state">${e.message}</div>`; }
}

// ============================================================
// Bootstrap
// ============================================================
document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("loginBtn");
  const errEl = document.getElementById("loginError");
  errEl.textContent = "";
  btn.disabled = true;
  try {
    await login(document.getElementById("loginUsername").value, document.getElementById("loginPassword").value);
  } catch (err) {
    errEl.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("avatarBtn").addEventListener("click", () => {
  if (confirm("Sign out?")) logout();
});

window.addEventListener("hashchange", () => {
  const route = location.hash.replace("#/", "");
  if (route && route !== state.route) navigate(route);
});

(async function boot() {
  const ok = await tryResumeSession();
  if (ok) onAuthenticated();
})();
