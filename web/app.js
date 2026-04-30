const state = {
  profiles: [],
  selectedProfile: null,
  activeTab: "identifiers",
  theme: "light",
  profileFilter: ""
};

const elements = {
  statusLine: document.querySelector("#statusLine"),
  themeButton: document.querySelector("#themeButton"),
  refreshButton: document.querySelector("#refreshButton"),
  exportButton: document.querySelector("#exportButton"),
  seedForm: document.querySelector("#seedForm"),
  seedInput: document.querySelector("#seedInput"),
  counts: document.querySelector("#counts"),
  profileCount: document.querySelector("#profileCount"),
  profileFilter: document.querySelector("#profileFilter"),
  profileList: document.querySelector("#profileList"),
  selectedProfileId: document.querySelector("#selectedProfileId"),
  profileDetail: document.querySelector("#profileDetail"),
  toolForm: document.querySelector("#toolForm"),
  toolInput: document.querySelector("#toolInput"),
  toolOpsec: document.querySelector("#toolOpsec"),
  toolCount: document.querySelector("#toolCount"),
  toolList: document.querySelector("#toolList"),
  metricTemplate: document.querySelector("#metricTemplate")
};

const THEME_KEY = "osint_ui_theme";
const MAX_TAB_ROWS = 250;
const MOON_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401" /></svg>';
const SUN_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2v2" /><path d="M12 20v2" /><path d="m4.93 4.93 1.41 1.41" /><path d="m17.66 17.66 1.41 1.41" /><path d="M2 12h2" /><path d="M20 12h2" /><path d="m6.34 17.66-1.41 1.41" /><path d="m19.07 4.93-1.41 1.41" /></svg>';

function text(value) {
  if (value === null || value === undefined || value === "") return "-";
  return String(value);
}

function pct(value) {
  const number = Number(value || 0);
  return `${Math.round(number * 100)}%`;
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function formatStamp(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === "-") return "-";
  const normalized = raw.includes("T") ? raw : raw.replace(" ", "T");
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return raw;
  return date.toLocaleString();
}

function setBusy(isBusy) {
  elements.refreshButton.disabled = isBusy;
  elements.exportButton.disabled = isBusy;
}

function resolveInitialTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function applyTheme(theme) {
  state.theme = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = state.theme;
  localStorage.setItem(THEME_KEY, state.theme);
  updateThemeButton();
}

function updateThemeButton() {
  const isDark = state.theme === "dark";
  const label = isDark ? "Switch to light theme" : "Switch to dark theme";
  elements.themeButton.title = label;
  elements.themeButton.setAttribute("aria-label", label);
  elements.themeButton.innerHTML = isDark ? SUN_ICON : MOON_ICON;
}

function toggleTheme() {
  applyTheme(state.theme === "dark" ? "light" : "dark");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return payload;
}

async function refresh() {
  setBusy(true);
  try {
    const data = await api("/api/database?limit=500");
    state.profiles = data.profiles || [];
    renderCounts(data.counts || {});
    renderProfiles();
    elements.statusLine.textContent = `Connected to PostgreSQL - ${new Date().toLocaleTimeString()}`;

    if (state.selectedProfile) {
      const exists = state.profiles.some(profile => profile.id === state.selectedProfile.id);
      if (exists) await selectProfile(state.selectedProfile.id);
      else if (state.profiles.length) await selectProfile(state.profiles[0].id);
      else state.selectedProfile = null;
    } else if (state.profiles.length) {
      await selectProfile(state.profiles[0].id);
    }
  } catch (error) {
    elements.statusLine.textContent = error.message;
    elements.counts.innerHTML = `<div class="detail-empty">${escapeHtml(error.message)}</div>`;
    elements.profileList.innerHTML = `<div class="detail-empty">Database is not available. Restart the app with the correct PostgreSQL password.</div>`;
  } finally {
    setBusy(false);
  }
}

function renderCounts(counts) {
  elements.counts.innerHTML = "";
  const items = [
    ["Profiles", counts.profiles],
    ["Finds", counts.identifiers],
    ["Evidence", counts.evidence],
    ["Searches", counts.searches],
    ["Connections", counts.connections],
    ["OSINT Tools", counts.osintTools],
    ["OSINT Categories", counts.osintCategories]
  ];

  for (const [label, value] of items) {
    const node = elements.metricTemplate.content.firstElementChild.cloneNode(true);
    node.querySelector(".metric-value").textContent = text(value);
    node.querySelector(".metric-label").textContent = label;
    elements.counts.appendChild(node);
  }
}

function filteredProfiles() {
  const query = state.profileFilter.trim().toLowerCase();
  if (!query) return state.profiles;
  return state.profiles.filter(profile => {
    const display = text(profile.display_name || profile.seed).toLowerCase();
    const seed = text(profile.seed).toLowerCase();
    const id = text(profile.id).toLowerCase();
    return display.includes(query) || seed.includes(query) || id.includes(query);
  });
}

function renderProfiles() {
  const profiles = filteredProfiles();
  elements.profileCount.textContent = state.profileFilter
    ? `${profiles.length}/${state.profiles.length} shown`
    : `${state.profiles.length} loaded`;
  elements.profileList.innerHTML = "";

  if (!profiles.length) {
    const message = state.profileFilter ? "No profiles match this filter." : "No profiles yet.";
    elements.profileList.innerHTML = `<div class="detail-empty">${message}</div>`;
    return;
  }

  for (const profile of profiles) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "profile-item";
    if (state.selectedProfile && state.selectedProfile.id === profile.id) {
      button.classList.add("active");
    }
    button.innerHTML = `
      <span class="profile-title">${escapeHtml(profile.display_name || profile.seed)}</span>
      <span class="profile-meta">
        <span class="badge">${text(profile.identifier_count)} finds</span>
        <span class="badge">${text(profile.evidence_count)} evidence</span>
        <span class="badge">${pct(profile.confidence)} confidence</span>
        <span class="badge">${escapeHtml(formatStamp(profile.created_at))}</span>
      </span>
    `;
    button.addEventListener("click", () => selectProfile(profile.id));
    elements.profileList.appendChild(button);
  }
}

async function selectProfile(id) {
  state.selectedProfile = await api(`/api/profiles/${id}`);
  elements.selectedProfileId.textContent = state.selectedProfile.id;
  renderProfiles();
  renderProfileDetail();
  const toolInput = toolInputForProfile(state.selectedProfile);
  if (toolInput) elements.toolInput.value = toolInput;
}

function renderProfileDetail() {
  const profile = state.selectedProfile;
  const identifiers = safeArray(profile?.identifiers);
  const evidence = safeArray(profile?.evidence);
  const searches = safeArray(profile?.searches);
  const connections = safeArray(profile?.connections);
  const links = identifierRows(profile);
  if (!profile) {
    elements.profileDetail.className = "detail-empty";
    elements.profileDetail.textContent = "No profile selected.";
    return;
  }

  elements.profileDetail.className = "detail-body";
  elements.profileDetail.innerHTML = `
    <div class="detail-summary">
      <div>
        <h3>${escapeHtml(profile.display_name || profile.seed)}</h3>
        <p>${escapeHtml(profile.summary)}</p>
      </div>
      <div class="detail-score">
        <span>Confidence</span>
        <strong>${pct(profile.confidence)}</strong>
        <span>${escapeHtml(formatStamp(profile.created_at))}</span>
      </div>
    </div>
    <div class="tabs">
      ${tabButton("identifiers", `Finds (${links.length})`)}
      ${tabButton("evidence", `Evidence (${evidence.length})`)}
      ${tabButton("searches", `Searches (${searches.length})`)}
      ${tabButton("coverage", `Coverage (${coverageRows(profile).length})`)}
      ${tabButton("connections", `Connections (${connections.length})`)}
    </div>
    <div id="tabContent"></div>
  `;

  for (const button of elements.profileDetail.querySelectorAll("[data-tab]")) {
    button.addEventListener("click", () => {
      state.activeTab = button.dataset.tab;
      renderProfileDetail();
    });
  }

  renderTabContent(profile);
}

function tabButton(tab, label) {
  const active = state.activeTab === tab ? " active" : "";
  return `<button type="button" class="${active}" data-tab="${tab}">${escapeHtml(label)}</button>`;
}

function renderTabContent(profile) {
  const target = document.querySelector("#tabContent");
  const evidence = safeArray(profile.evidence);
  const searches = safeArray(profile.searches);
  const connections = safeArray(profile.connections);
  if (state.activeTab === "identifiers") {
    const links = identifierRows(profile);
    target.innerHTML = table(["Link", "Confidence", "Source"], links, item => [
      linkIfUrl(item.value), pct(item.confidence), item.source
    ], { maxRows: MAX_TAB_ROWS });
  } else if (state.activeTab === "evidence") {
    target.innerHTML = table(["Type", "Title", "Snippet", "Confidence"], evidence, item => [
      item.source_type, item.title, item.snippet, pct(item.confidence)
    ], { maxRows: MAX_TAB_ROWS });
  } else if (state.activeTab === "searches") {
    target.innerHTML = table(["Query", "Status", "Results", "Created"], searches, item => [
      item.query, item.status, item.result_count, formatStamp(item.created_at)
    ], { maxRows: MAX_TAB_ROWS });
  } else if (state.activeTab === "coverage") {
    const rows = coverageRows(profile);
    target.innerHTML = table(["Category", "Type", "Item", "Status"], rows, item => [
      item.category,
      item.type,
      item.item,
      item.status
    ], { maxRows: MAX_TAB_ROWS });
  } else {
    target.innerHTML = table(["Relationship", "From", "To", "Confidence", "Source"], connections, item => [
      item.relationship_type, item.from_profile_id, item.to_profile_id, pct(item.confidence), item.source
    ], { maxRows: MAX_TAB_ROWS });
  }
}

function identifierRows(profile) {
  if (!profile) return [];
  const rows = [];
  const seen = new Set();

  function add(kind, value, confidence, source) {
    const link = text(value).trim();
    if (!(link.startsWith("http://") || link.startsWith("https://"))) return;
    const key = link.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    rows.push({ kind, value: link, confidence: Number(confidence || 0), source });
  }

  for (const item of profile.identifiers || []) {
    const kind = text(item.kind);
    const source = text(item.source);
    const isVerified = kind === "verified_profile_link" || source.startsWith("found:");
    const isSeedUrl = kind === "seed_link" || (kind === "url" && source === "seed");
    if (isVerified) add("verified_find", item.value, item.confidence, source);
    else if (isSeedUrl) add("seed_link", item.value, item.confidence, source);
  }

  for (const evidence of profile.evidence || []) {
    if (text(evidence.source_type) === "seed") continue;
    const uri = text(evidence.source_uri);
    if (!(uri.startsWith("http://") || uri.startsWith("https://"))) continue;
    add("verified_find", uri, evidence.confidence, `found:${text(evidence.source_type)}`);
  }

  return rows;
}

function coverageRows(profile) {
  const rows = [];
  for (const search of safeArray(profile.searches)) {
    if (search.status === "category_queued") {
      rows.push(parseCategoryRow(search));
    } else if (search.status === "tool_queued") {
      rows.push(parseToolRow(search));
    }
  }
  return rows;
}

function parseCategoryRow(search) {
  const query = text(search.query);
  const category = query.startsWith("category:") ? query.slice("category:".length).split(" | ")[0] : query;
  return {
    category,
    type: "Category",
    item: "All tools in category are queued",
    status: `${search.status} (${search.result_count} tools)`
  };
}

function parseToolRow(search) {
  const query = text(search.query);
  const parts = query.startsWith("tool:") ? query.slice("tool:".length).split(" | ") : [query];
  const category = parts[0] || "Unknown";
  const name = parts[1] || "Tool";
  const url = parts[2] || "";
  const item = url
    ? rawHtml(`${escapeHtml(name)}<br><a href="${escapeAttribute(url)}" target="_blank" rel="noreferrer">${escapeHtml(url)}</a>`)
    : name;
  return {
    category,
    type: "Tool",
    item,
    status: search.status
  };
}

function linkIfUrl(value) {
  const rendered = text(value);
  if (rendered.startsWith("http://") || rendered.startsWith("https://")) {
    return rawHtml(`<a href="${escapeAttribute(rendered)}" target="_blank" rel="noreferrer">${escapeHtml(rendered)}</a>`);
  }
  return rendered;
}

function toolInputForProfile(profile) {
  const order = ["email", "handle", "username_candidate", "domain", "phone", "url", "free_text"];
  const identifiers = safeArray(profile?.identifiers);
  for (const kind of order) {
    const match = identifiers.find(identifier => identifier.kind === kind);
    if (!match) continue;
    if (kind === "handle" || kind === "username_candidate") return "username";
    if (kind === "phone") return "phone";
    if (kind === "free_text") return "people";
    return kind;
  }
  return "";
}

function table(headers, rows, mapper, options = {}) {
  if (!rows.length) return `<div class="detail-empty">No rows.</div>`;
  const maxRows = Number(options.maxRows || rows.length);
  const limitedRows = rows.slice(0, maxRows);
  const note = rows.length > limitedRows.length
    ? `<p class="table-note">Showing ${limitedRows.length} of ${rows.length} rows. Use export for full data.</p>`
    : "";
  return `
    ${note}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>${headers.map(header => `<th>${escapeHtml(header)}</th>`).join("")}</tr>
        </thead>
        <tbody>
          ${limitedRows.map(row => `<tr>${mapper(row).map(renderCell).join("")}</tr>`).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderCell(value) {
  if (value && typeof value === "object" && value.__html === true) {
    return `<td>${value.value}</td>`;
  }
  return `<td>${escapeHtml(text(value))}</td>`;
}

function rawHtml(value) {
  return { __html: true, value };
}

async function createProfile(event) {
  event.preventDefault();
  const seed = elements.seedInput.value.trim();
  if (!seed) return;

  const submit = elements.seedForm.querySelector("button");
  submit.disabled = true;
  try {
    const profile = await api("/api/profiles", {
      method: "POST",
      body: JSON.stringify({ seed })
    });
    elements.seedInput.value = "";
    state.selectedProfile = profile;
    await refresh();
    await selectProfile(profile.id);
    elements.statusLine.textContent = `Profile created: ${text(profile.display_name || profile.seed)}`;
  } catch (error) {
    elements.statusLine.textContent = error.message;
  } finally {
    submit.disabled = false;
  }
}

async function searchTools(event) {
  if (event) event.preventDefault();
  const input = encodeURIComponent(elements.toolInput.value.trim() || "email");
  const opsec = elements.toolOpsec.value ? `&opsec=${encodeURIComponent(elements.toolOpsec.value)}` : "";
  try {
    const data = await api(`/api/tools?input=${input}${opsec}&limit=50`);
    renderTools(data.tools || []);
  } catch (error) {
    elements.toolList.innerHTML = `<div class="detail-empty">${escapeHtml(error.message)}</div>`;
  }
}

function renderTools(tools) {
  elements.toolCount.textContent = `${tools.length} shown`;
  elements.toolList.innerHTML = "";
  if (!tools.length) {
    elements.toolList.innerHTML = `<div class="detail-empty">No matching tools.</div>`;
    return;
  }

  for (const tool of tools) {
    const row = document.createElement("div");
    row.className = "tool-item";
    const statusClass = tool.deprecated ? "red" : (tool.opsec === "passive" ? "green" : "amber");
    row.innerHTML = `
      <span class="tool-title">${escapeHtml(tool.name)}</span>
      <div class="tool-meta">
        <span class="badge">${escapeHtml(tool.framework_path)}</span>
        <span class="badge ${statusClass}">${escapeHtml(tool.opsec || "opsec unknown")}</span>
        ${tool.api ? `<span class="badge green">API</span>` : ""}
        ${tool.registration ? `<span class="badge amber">Registration</span>` : ""}
        ${tool.local_install ? `<span class="badge amber">Local install</span>` : ""}
      </div>
      ${tool.url ? `<p><a href="${escapeAttribute(tool.url)}" target="_blank" rel="noreferrer">${escapeHtml(tool.url)}</a></p>` : ""}
      ${tool.description ? `<p>${escapeHtml(tool.description)}</p>` : ""}
    `;
    elements.toolList.appendChild(row);
  }
}

async function exportDatabase() {
  setBusy(true);
  try {
    const data = await api("/api/database?limit=500");
    const profiles = [];
    for (const profile of data.profiles || []) {
      profiles.push(await api(`/api/profiles/${profile.id}`));
    }
    const blob = new Blob([JSON.stringify({ counts: data.counts, profiles }, null, 2)], {
      type: "application/json"
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `osint-export-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    elements.statusLine.textContent = `Exported ${profiles.length} profiles to JSON`;
  } catch (error) {
    elements.statusLine.textContent = error.message;
  } finally {
    setBusy(false);
  }
}

function escapeHtml(value) {
  return text(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#96;");
}

elements.refreshButton.addEventListener("click", refresh);
elements.exportButton.addEventListener("click", exportDatabase);
elements.themeButton.addEventListener("click", toggleTheme);
elements.seedForm.addEventListener("submit", createProfile);
elements.toolForm.addEventListener("submit", searchTools);
elements.profileFilter.addEventListener("input", event => {
  state.profileFilter = String(event.target.value || "");
  renderProfiles();
});

applyTheme(resolveInitialTheme());
refresh();
searchTools();
