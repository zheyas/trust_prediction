"use strict";

/* ========================================================================
 * Клиент веб-интерфейса прогнозирования доверия (ГОСТ Р ИСО/МЭК 27034-7-2020)
 * Ванильный JS, без сборки и внешних зависимостей — общается с локальным
 * API (webapp.py) тем же способом, каким CLI обращается к workflow.py.
 * ======================================================================== */

const STATE = {
  data: null,
  raci: null,
  view: "overview",
  versionId: null,
  analyze: {}, // versionId -> { changeId: {label,score} } последний результат анализа (не персистится)
};

const CATEGORY_LABELS = {
  code: "Код",
  architecture: "Архитектура",
  test_methodology: "Методика тестирования",
  configuration: "Конфигурация",
  other: "Иное",
};
const SUBST_LABELS = {
  substantial: "Существенное",
  borderline: "Пограничное",
  not_substantial: "Несущественное",
};
const SUBST_BADGE = {
  substantial: "badge-danger",
  borderline: "badge-warning",
  not_substantial: "badge-success",
};
const POLICY_LABELS = {
  forbidden: "Запрещено (FORBIDDEN)",
  conditional: "Условно (CONDITIONAL)",
  unrestricted: "Неограниченно (UNRESTRICTED)",
};
const OUTCOME_LABELS = { pending: "Ожидание", pass: "PASS", fail: "FAIL" };
const STATUS_LABELS = {
  planned: "Не начато",
  predicted: "Прогноз (ПОБП)",
  executed: "Выполнено фактически",
};
const DECISION_LABELS = { pending: "Ожидание", approved: "Утверждено", rejected: "Отклонено" };

const CONTROL_CATEGORY_OPTIONS = [
  { value: "code", label: "Код (SAST/SCA)" },
  { value: "architecture", label: "Архитектура / моделирование угроз" },
  { value: "test", label: "Тестирование (DAST/пентест)" },
  { value: "configuration", label: "Конфигурация" },
  { value: "access", label: "Контроль доступа" },
  { value: "crypto", label: "Криптография" },
  { value: "logging", label: "Логирование и мониторинг" },
  { value: "general", label: "Общая" },
];
const COMMON_CONTROL_NAMES = [
  "Статический анализ кода (SAST)",
  "Анализ состава зависимостей (SCA)",
  "Динамическое тестирование (DAST)",
  "Архитектурный анализ угроз (Threat modeling)",
  "Ревью контроля доступа",
  "Проверка конфигурации окружения",
  "Пентест",
  "Ревью кода",
  "Проверка криптографии",
  "Анализ секретов в репозитории",
  "IaC-сканирование инфраструктуры",
  "Проверка логирования и мониторинга",
];

/* ------------------------------------------------------------------ API */

async function api(path, method = "GET", body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let payload = null;
  try { payload = await res.json(); } catch (e) { /* пусто */ }
  if (!res.ok) {
    const msg = (payload && payload.error) || `Ошибка запроса (${res.status})`;
    throw new Error(msg);
  }
  return payload;
}

/* --------------------------------------------------------------- toasts */

function toast(message, isError) {
  const wrap = document.getElementById("toasts");
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.textContent = message;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 4600);
}

function fail(err) {
  console.error(err);
  toast(err.message || String(err), true);
}

/** Скачивает файл через fetch (а не голой ссылкой), чтобы показать
 * дружелюбную ошибку тостом, если сервер ответил не файлом (например,
 * PDF ещё недоступен без установленной библиотеки fpdf2). */
async function downloadFile(url, fallbackFilename, button) {
  const prevText = button ? button.textContent : null;
  if (button) { button.disabled = true; button.textContent = "Формирование…"; }
  try {
    const res = await fetch(url);
    if (!res.ok) {
      let msg = `Ошибка (${res.status})`;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (e) { /* не json */ }
      throw new Error(msg);
    }
    const blob = await res.blob();
    const disposition = res.headers.get("Content-Disposition") || "";
    const match = /filename="([^"]+)"/.exec(disposition);
    const filename = match ? match[1] : fallbackFilename;
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 4000);
  } catch (err) {
    fail(err);
  } finally {
    if (button) { button.disabled = false; button.textContent = prevText; }
  }
}

/* --------------------------------------------------------------- modal */

function openModal(title, bodyEl) {
  document.getElementById("modal-title").textContent = title;
  document.querySelector(".modal").style.maxWidth = "";
  const body = document.getElementById("modal-body");
  body.innerHTML = "";
  body.appendChild(bodyEl);
  document.getElementById("modal-backdrop").hidden = false;
}
function closeModal() {
  document.getElementById("modal-backdrop").hidden = true;
  document.getElementById("modal-body").innerHTML = "";
}

/* ------------------------------------------------------------- helpers */

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function fmtDate(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString("ru-RU", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  } catch (e) { return iso; }
}
function shortId(id) { return id ? id.split("-")[0] + "-" + id.split("-").slice(-1)[0].slice(0, 5) : ""; }
function pct(fraction) { return Math.round(fraction * 1000) / 10; }
function controlOptions(selectedIds) {
  selectedIds = selectedIds || [];
  return (STATE.data.controls || [])
    .map((c) => `<label><input type="checkbox" name="controls" value="${c.id}" ${selectedIds.includes(c.id) ? "checked" : ""}> ${esc(c.name)} ${c.critical ? '<span class="badge badge-danger">крит.</span>' : ""}</label>`)
    .join("");
}
function versionById(id) { return (STATE.data.versions || []).find((v) => v.id === id); }
function controlById(id) { return (STATE.data.controls || []).find((c) => c.id === id); }

/* --------------------------------------------------- выпадающие списки с
 * возможностью ввести своё значение ("Другое…") — переиспользуемый паттерн
 * для категорий и полей-акторов (роль/имя исполнителя). */

function selectWithCustomHTML(name, groups, { preset, placeholder } = {}) {
  const flat = groups.flatMap((g) => g.options);
  const presetIsKnown = preset != null && flat.some((o) => o.value === preset);
  const renderOpts = (opts) => opts.map((o) =>
    `<option value="${esc(o.value)}" ${presetIsKnown && o.value === preset ? "selected" : ""}>${esc(o.label)}</option>`
  ).join("");
  const groupsHtml = groups.map((g) =>
    g.label
      ? `<optgroup label="${esc(g.label)}">${renderOpts(g.options)}</optgroup>`
      : renderOpts(g.options)
  ).join("");
  const showCustom = preset != null && !presetIsKnown;
  return `
    <select name="${name}" data-has-custom>
      <option value="">— выбрать —</option>
      ${groupsHtml}
      <option value="__custom__" ${showCustom ? "selected" : ""}>Другое (ввести вручную)…</option>
    </select>
    <input type="text" data-custom-for="${name}" placeholder="${esc(placeholder || "Введите значение")}"
      value="${showCustom ? esc(preset) : ""}" style="${showCustom ? "margin-top:6px;" : "display:none;margin-top:6px;"}">
  `;
}

function wireCustomSelects(root) {
  root.querySelectorAll("select[data-has-custom]").forEach((sel) => {
    // Scope the lookup to the select's own <form> (falling back to root)
    // rather than searching the whole root: a root can contain several
    // sibling forms that reuse the same field name (e.g. "actor" in the
    // verify/audit/assess forms), and an unscoped querySelector would
    // always grab the first match in document order, wiring the wrong
    // custom-input to this select.
    const scope = sel.closest("form") || root;
    const custom = scope.querySelector(`[data-custom-for="${sel.name}"]`);
    if (!custom) return;
    const sync = () => {
      const isCustom = sel.value === "__custom__";
      custom.style.display = isCustom ? "" : "none";
      if (isCustom) custom.focus();
    };
    sel.addEventListener("change", sync);
  });
}

function resolveField(form, name) {
  const sel = form.querySelector(`select[name="${name}"][data-has-custom]`);
  if (sel) {
    if (sel.value === "__custom__") {
      const custom = form.querySelector(`[data-custom-for="${name}"]`);
      return custom ? custom.value.trim() : "";
    }
    return sel.value;
  }
  const plain = form.querySelector(`[name="${name}"]`);
  return plain ? plain.value : "";
}

/** Роли (из матрицы RACI) + ранее использованные в проекте имена/роли —
 * для полей-акторов (инициатор, представитель НСО, владелец, исполнитель…). */
function actorGroups() {
  const roleLabels = (STATE.raci?.actors || []).map((a) => a.label);
  const known = knownActors().filter((a) => !roleLabels.includes(a));
  const groups = [];
  if (roleLabels.length) groups.push({ label: "Роли (по умолчанию)", options: roleLabels.map((l) => ({ value: l, label: l })) });
  if (known.length) groups.push({ label: "Ранее использованные", options: known.map((l) => ({ value: l, label: l })) });
  return groups;
}
function knownActors() {
  const set = new Set();
  if (STATE.data.application?.owner) set.add(STATE.data.application.owner);
  (STATE.data.audit_log || []).forEach((e) => { if (e.actor) set.add(e.actor); });
  (STATE.data.versions || []).forEach((v) => {
    (v.executions || []).forEach((e) => { if (e.executed_by) set.add(e.executed_by); });
    (v.pasrs || []).forEach((p) => { Object.values(p.actors || {}).forEach((a) => { if (a) set.add(a); }); });
  });
  return Array.from(set).sort((a, b) => a.localeCompare(b, "ru"));
}
function actorFieldHTML(name, preset, placeholder) {
  return selectWithCustomHTML(name, actorGroups(), { preset, placeholder: placeholder || "Введите имя или роль" });
}

/* ------------------------------------------------------------------ load */

async function loadAll() {
  const [data, raciData] = await Promise.all([api("/api/state"), api("/api/raci")]);
  STATE.data = data;
  STATE.raci = raciData;
  if (STATE.view === "version" && STATE.versionId && !versionById(STATE.versionId)) {
    STATE.view = "overview";
    STATE.versionId = null;
  }
  render();
}

async function refresh() {
  STATE.data = await api("/api/state");
  render();
}

/* ------------------------------------------------------------------ nav */

function goto(view, versionId) {
  STATE.view = view;
  STATE.versionId = versionId || null;
  render();
  document.querySelector(".content").scrollTo?.({ top: 0 });
  window.scrollTo(0, 0);
}

/* ==========================================================================
 * RENDER
 * ======================================================================== */

function render() {
  renderSidebar();
  renderTopbar();
  const content = document.getElementById("content");
  content.innerHTML = "";
  if (!STATE.data.application) {
    content.appendChild(renderNoApplication());
  } else if (STATE.view === "overview") {
    content.appendChild(renderOverview());
  } else if (STATE.view === "raci") {
    content.appendChild(renderRaciView());
  } else if (STATE.view === "log") {
    content.appendChild(renderLogView());
  } else if (STATE.view === "version" && STATE.versionId) {
    const v = versionById(STATE.versionId);
    if (v) content.appendChild(renderVersionView(v));
  }
}

function renderTopbar() {
  const titles = { overview: "Обзор и МОБП", raci: "Матрица RACI", log: "Журнал аудита" };
  let title = titles[STATE.view] || "Прогноз доверия";
  if (STATE.view === "version" && STATE.versionId) {
    const v = versionById(STATE.versionId);
    title = v ? `Версия «${v.label}»` : "Версия";
  }
  document.getElementById("topbar-title").textContent = title;
  const app = STATE.data.application;
  document.getElementById("topbar-app").textContent = app ? `${app.name} · ${app.owner}` : "";

  const banner = document.getElementById("demo-banner");
  banner.hidden = STATE.data.active_project !== "demo";
}

function renderSidebar() {
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.classList.toggle("active", STATE.view === b.dataset.nav);
  });

  const wrap = document.getElementById("nav-versions");
  wrap.innerHTML = "";
  const versions = STATE.data.versions || [];
  if (!versions.length) {
    wrap.appendChild(el(`<div class="nav-empty">Версий пока нет</div>`));
  }
  versions.slice().reverse().forEach((v) => {
    const p = pct(v.trust.fraction);
    const btn = el(`
      <button class="nav-version ${STATE.view === "version" && STATE.versionId === v.id ? "active" : ""}">
        <div class="nav-version-top">
          <span class="nav-version-label">${esc(v.label)} ${v.is_reference ? "&#9733;" : ""}</span>
          <span class="nav-version-pct">${p}%</span>
        </div>
        <div class="nav-version-bar"><span style="width:${Math.min(100, p)}%; background:${v.trust.meets_target ? "var(--accent)" : "var(--danger)"}"></span></div>
      </button>`);
    btn.addEventListener("click", () => goto("version", v.id));
    wrap.appendChild(btn);
  });
}

/* -------------------------------------------------------- нет приложения */

function renderNoApplication() {
  const wrap = el(`<div class="card" style="max-width:460px;margin:40px auto;">
    <div class="empty-state" style="padding-bottom:6px;">
      <div class="big">&#128272;</div>
      <h2>Начните с регистрации приложения</h2>
      <p class="muted">Создайте приложение, для которого будет вестись прогнозирование доверия по ГОСТ Р ИСО/МЭК 27034-7-2020, либо загрузите готовый демонстрационный сценарий.</p>
    </div>
    <form id="form-app">
      <div class="field"><label>Название приложения</label><input type="text" name="name" required placeholder="Например, «Портал электронного документооборота»"></div>
      <div class="field"><label>Владелец приложения</label><input type="text" name="owner" required placeholder="Например, ООО «Компания»"></div>
      <div class="form-actions">
        <button type="button" class="btn btn-secondary" id="btn-try-demo">Загрузить демо-сценарий</button>
        <button type="submit" class="btn btn-primary">Создать приложение</button>
      </div>
    </form>
  </div>`);
  wrap.querySelector("#form-app").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/application", "POST", { name: fd.get("name"), owner: fd.get("owner") });
      toast("Приложение создано");
      await refresh();
    } catch (err) { fail(err); }
  });
  wrap.querySelector("#btn-try-demo").addEventListener("click", () => runDemo());
  return wrap;
}

/* ------------------------------------------------------------- overview */

function renderOverview() {
  const wrap = document.createDocumentFragment();
  const app = STATE.data.application;

  const appCard = el(`<div class="card">
    <div class="card-head"><h2>Приложение</h2></div>
    <form id="form-app-edit">
      <div class="form-row">
        <div class="field"><label>Название</label><input type="text" name="name" value="${esc(app.name)}" required></div>
        <div class="field"><label>Владелец</label><input type="text" name="owner" value="${esc(app.owner)}" required></div>
      </div>
      <div class="form-actions"><button type="submit" class="btn btn-secondary btn-small">Сохранить</button></div>
    </form>
  </div>`);
  appCard.querySelector("#form-app-edit").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/application", "POST", { name: fd.get("name"), owner: fd.get("owner") });
      toast("Данные приложения обновлены");
      await refresh();
    } catch (err) { fail(err); }
  });
  wrap.appendChild(appCard);

  const policyCard = el(`<div class="card">
    <div class="card-head"><h2>Шаг 1 — Политика прогнозирования (НСО)</h2>
      <span class="badge badge-accent">${esc(POLICY_LABELS[STATE.data.policy] || STATE.data.policy)}</span>
    </div>
    <p class="card-sub">Группа НСО задаёт методологию: допустимость прогнозирования и пороги оценки существенности изменений (раздел 7).</p>
    <form id="form-policy">
      <div class="form-row">
        <div class="field"><label>Политика</label>
          <select name="policy">
            ${Object.entries(POLICY_LABELS).map(([k, v]) => `<option value="${k}" ${STATE.data.policy === k ? "selected" : ""}>${v}</option>`).join("")}
          </select>
        </div>
        <div class="field"><label>Представитель НСО (актор)</label>${actorFieldHTML("actor", "Группа НСО")}</div>
      </div>
      <div class="form-row">
        <div class="field"><label>Порог «существенное», &ge;</label>
          <div class="range-row"><input type="range" name="substantial" min="0" max="1" step="0.05" value="${STATE.data.substantial_threshold}"><span class="range-val" data-out="substantial">${STATE.data.substantial_threshold}</span></div>
        </div>
        <div class="field"><label>Порог «пограничное», &ge;</label>
          <div class="range-row"><input type="range" name="borderline" min="0" max="1" step="0.05" value="${STATE.data.borderline_threshold}"><span class="range-val" data-out="borderline">${STATE.data.borderline_threshold}</span></div>
        </div>
      </div>
      <div class="form-actions"><button type="submit" class="btn btn-primary btn-small">Применить политику</button></div>
    </form>
  </div>`);
  wireRangeOutputs(policyCard);
  wireCustomSelects(policyCard);
  policyCard.querySelector("#form-policy").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/policy", "POST", {
        policy: fd.get("policy"), actor: resolveField(e.target, "actor"),
        substantial: parseFloat(fd.get("substantial")), borderline: parseFloat(fd.get("borderline")),
      });
      toast("Политика прогнозирования обновлена");
      await refresh();
    } catch (err) { fail(err); }
  });
  wrap.appendChild(policyCard);

  const controlsCard = el(`<div class="card">
    <div class="card-head">
      <h2>Меры обеспечения безопасности приложений (МОБП)</h2>
      <button class="btn btn-primary btn-small" id="btn-add-control">+ Добавить меру</button>
    </div>
    <div class="table-wrap" id="controls-table"></div>
  </div>`);
  controlsCard.querySelector("#controls-table").appendChild(renderControlsTable());
  controlsCard.querySelector("#btn-add-control").addEventListener("click", openAddControlModal);
  wrap.appendChild(controlsCard);

  return wrap;
}

function renderControlsTable() {
  const controls = STATE.data.controls || [];
  if (!controls.length) {
    return el(`<div class="empty-state"><div class="big">&#128736;</div>Мер пока нет — добавьте первую МОБП.</div>`);
  }
  const rows = controls.map((c) => `
    <tr>
      <td><b>${esc(c.name)}</b>${c.description ? `<div class="faint">${esc(c.description)}</div>` : ""}</td>
      <td>${esc(c.category)}</td>
      <td>${c.weight}</td>
      <td>${c.critical ? '<span class="badge badge-danger">критическая</span>' : '<span class="badge badge-neutral">обычная</span>'}</td>
      <td class="mono faint">${shortId(c.id)}</td>
    </tr>`).join("");
  return el(`<table class="table">
    <thead><tr><th>Мера</th><th>Категория</th><th>Вес</th><th>Тип</th><th>ID</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`);
}

function openAddControlModal() {
  const body = el(`<form id="form-control">
    <div class="field"><label>Название меры</label>
      <input type="text" name="name" list="control-name-suggestions" required placeholder="Выберите из списка или введите своё">
      <datalist id="control-name-suggestions">${COMMON_CONTROL_NAMES.map((n) => `<option value="${esc(n)}">`).join("")}</datalist>
    </div>
    <div class="form-row">
      <div class="field"><label>Категория</label>
        ${selectWithCustomHTML("category", [{ options: CONTROL_CATEGORY_OPTIONS }], { preset: "general", placeholder: "Своя категория" })}
      </div>
      <div class="field"><label>Вес</label><input type="number" name="weight" value="1.0" min="0" step="0.1"></div>
    </div>
    <div class="field"><label>Тип меры</label>
      <select name="critical">
        <option value="false" selected>Обычная мера</option>
        <option value="true">Критическая (обязательна верификация при переносе через ПОБП)</option>
      </select>
    </div>
    <div class="field"><label>Описание (необязательно)</label><textarea name="description"></textarea></div>
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" id="cc-cancel">Отмена</button>
      <button type="submit" class="btn btn-primary">Добавить меру</button>
    </div>
  </form>`);
  wireCustomSelects(body);
  body.querySelector("#cc-cancel").addEventListener("click", closeModal);
  body.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/controls", "POST", {
        name: fd.get("name"), category: resolveField(e.target, "category"),
        weight: parseFloat(fd.get("weight") || "1"), critical: fd.get("critical") === "true",
        description: fd.get("description"),
      });
      toast("Мера добавлена");
      closeModal();
      await refresh();
    } catch (err) { fail(err); }
  });
  openModal("Новая мера обеспечения безопасности (МОБП)", body);
}

/* ------------------------------------------------------------------ RACI */

function renderRaciView() {
  const wrap = el(`<div class="card"></div>`);
  wrap.appendChild(el(`<div class="card-head"><h2>Матрица RACI — десять шагов процесса (раздел 12.2)</h2></div>`));
  wrap.appendChild(el(`<p class="card-sub">О — ответственность, П — подотчётность, К — консультирование, И — информирование. Референсная конфигурация ролей по умолчанию (раздел 9.5) — адаптируйте под свою НСО.</p>`));
  wrap.appendChild(renderRaciTable());
  return wrap;
}

function renderRaciTable() {
  const r = STATE.raci;
  const letters = { R: "О", A: "П", C: "К", I: "И", "-": "&mdash;" };
  const badgeClass = { R: "badge-accent", A: "badge-danger", C: "badge-warning", I: "badge-info", "-": "badge-neutral" };
  const head = `<tr><th style="min-width:280px;">Шаг процесса</th>${r.actors.map((a) => `<th>${esc(a.label)}</th>`).join("")}</tr>`;
  const rows = r.steps.map((title, i) => {
    const idx = String(i + 1);
    const cells = r.actors.map((a) => {
      const role = r.matrix[idx][a.key];
      return `<td><span class="badge ${badgeClass[role]}">${letters[role]}</span></td>`;
    }).join("");
    return `<tr><td>${i + 1}. ${esc(title.replace(/^\d+\.\s*/, ""))}</td>${cells}</tr>`;
  }).join("");
  return el(`<div class="table-wrap"><table class="table">${head}${rows}</table></div>`);
}

/* -------------------------------------------------------------------- log */

function renderLogView() {
  const wrap = el(`<div class="card"><div class="card-head"><h2>Журнал аудита процесса</h2></div><div class="table-wrap" id="log-table"></div></div>`);
  const entries = STATE.data.audit_log || [];
  if (!entries.length) {
    wrap.querySelector("#log-table").appendChild(el(`<div class="empty-state">Журнал пока пуст.</div>`));
  } else {
    const rows = entries.map((e) => `
      <tr>
        <td class="faint mono" style="white-space:nowrap;">${fmtDate(e.timestamp)}</td>
        <td><span class="badge badge-neutral">${esc(e.step)}</span></td>
        <td>${esc(e.actor)}</td>
        <td>${esc(e.details)}</td>
      </tr>`).join("");
    wrap.querySelector("#log-table").appendChild(el(`<table class="table">
      <thead><tr><th>Время</th><th>Шаг</th><th>Актор</th><th>Событие</th></tr></thead>
      <tbody>${rows}</tbody></table>`));
  }
  return wrap;
}

/* --------------------------------------------------------------- версия */

function renderVersionView(v) {
  const wrap = document.createDocumentFragment();

  wrap.appendChild(renderVersionHeaderCard(v));
  wrap.appendChild(renderChangesCard(v));
  wrap.appendChild(renderControlsExecutionCard(v));
  wrap.appendChild(renderPasrCard(v));
  wrap.appendChild(renderProcessActionsCard(v));

  return wrap;
}

function renderVersionHeaderCard(v) {
  const parent = v.parent_version_id ? versionById(v.parent_version_id) : null;
  const good = v.trust.meets_target;
  const card = el(`<div class="card">
    <div class="card-head">
      <h2>Версия «${esc(v.label)}» ${v.is_reference ? '<span class="badge badge-accent">эталонная</span>' : '<span class="badge badge-neutral">производная</span>'}</h2>
      <span class="faint">создана ${fmtDate(v.created_at)}</span>
    </div>
    <div class="gauge-row">
      <div class="gauge ${good ? "" : "bad"}" style="--pct:${Math.min(100, pct(v.trust.fraction))}">
        <div class="gauge-value-wrap">
          <div class="gauge-value">${pct(v.trust.fraction)}%</div>
          <div class="gauge-target">цель ${Math.round(v.target_trust_threshold * 100)}%</div>
        </div>
      </div>
      <div class="gauge-meta">
        <div class="kv"><b>Тип уровня доверия</b> ${v.trust_kind === "actual" ? "Фактический (раздел 5)" : "Ожидаемый (раздел 5)"}</div>
        <div class="kv"><b>Статус относительно цели</b> ${good ? '<span class="badge badge-success">достигнут</span>' : '<span class="badge badge-danger">не достигнут</span>'}</div>
        <div class="kv"><b>Эталонная версия</b> ${parent ? `<a href="#" data-goto-version="${parent.id}">${esc(parent.label)}</a>` : "— (сама эталонная)"}</div>
        <div class="kv"><b>Суммарный вес мер</b> ${v.trust.counted_weight} / ${v.trust.total_weight}</div>
      </div>
    </div>
    <button class="btn btn-hero" id="btn-report-hero">&#128196; Получить отчёт</button>
    <details style="margin-top:14px;">
      <summary class="muted" style="cursor:pointer;font-size:12.5px;">Разбивка по мерам</summary>
      <div class="table-wrap" style="margin-top:10px;">
        <table class="table">
          <thead><tr><th>Мера</th><th>Вес</th><th>Учтена</th><th>Обоснование</th></tr></thead>
          <tbody>${v.trust.breakdown.map((b) => `<tr><td>${esc(b.control_name)}</td><td>${b.weight}</td><td>${b.counted ? '<span class="badge badge-success">да</span>' : '<span class="badge badge-neutral">нет</span>'}</td><td class="faint">${esc(b.reason)}</td></tr>`).join("")}</tbody>
        </table>
      </div>
    </details>
  </div>`);
  const link = card.querySelector("[data-goto-version]");
  if (link) link.addEventListener("click", (e) => { e.preventDefault(); goto("version", link.dataset.gotoVersion); });
  card.querySelector("#btn-report-hero").addEventListener("click", () => openReportModal(v));
  return card;
}

function renderChangesCard(v) {
  const analyzeResults = STATE.analyze[v.id] || {};
  const card = el(`<div class="card">
    <div class="card-head">
      <h2>Изменения версии (раздел 7 — анализ существенности)</h2>
      <div class="pill-row">
        <button class="btn btn-secondary btn-small" id="btn-analyze">Выполнить анализ риска</button>
        <button class="btn btn-primary btn-small" id="btn-add-change">+ Добавить изменение</button>
      </div>
    </div>
    <div id="changes-body"></div>
  </div>`);

  const body = card.querySelector("#changes-body");
  if (!v.changes.length) {
    body.appendChild(el(`<div class="empty-state"><div class="big">&#128203;</div>Изменений пока не зарегистрировано. Для эталонной версии это ожидаемо.</div>`));
  } else {
    const rows = v.changes.map((c) => {
      const ctrlNames = c.affected_control_ids.map((id) => (controlById(id) || {}).name || id).join(", ") || "—";
      let subst = `<span class="faint">не проанализировано</span>`;
      const a = STATE.analyze[v.id] && STATE.analyze[v.id][c.id];
      if (a) {
        subst = `<span class="badge ${SUBST_BADGE[a.label]}">${SUBST_LABELS[a.label] || a.label}</span> <span class="faint">score=${a.score}</span>`;
      }
      return `<tr>
        <td><b>${esc(c.description)}</b>${c.notes ? `<div class="faint">${esc(c.notes)}</div>` : ""}</td>
        <td>${CATEGORY_LABELS[c.category] || c.category}</td>
        <td>${esc(ctrlNames)}</td>
        <td>${c.analyst_risk_impact}</td>
        <td>${subst}</td>
      </tr>`;
    }).join("");
    body.appendChild(el(`<div class="table-wrap"><table class="table">
      <thead><tr><th>Описание</th><th>Категория</th><th>Затронутые меры</th><th>Влияние на риск</th><th>Существенность</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`));
  }

  card.querySelector("#btn-add-change").addEventListener("click", () => openAddChangeModal(v));
  card.querySelector("#btn-analyze").addEventListener("click", async () => {
    try {
      const res = await api(`/api/versions/${v.id}/analyze`, "POST", { actor: "Эксперт предметной области" });
      STATE.analyze[v.id] = {};
      Object.entries(res.recommendations).forEach(([cid, rec]) => {
        // recommendations — по мерам; сопоставим наихудшую оценку с изменениями, влияющими на эту меру
        v.changes.forEach((c) => {
          if (c.affected_control_ids.includes(cid) && rec.label !== "not_affected") {
            STATE.analyze[v.id][c.id] = rec;
          }
        });
      });
      toast(res.message);
      await refresh();
    } catch (err) { fail(err); }
  });

  return card;
}

function openAddChangeModal(v) {
  const body = el(`<form id="form-change">
    <div class="field"><label>Описание изменения</label><input type="text" name="description" required placeholder="Например, «Рефакторинг модуля аутентификации»"></div>
    <div class="field"><label>Категория</label>
      <select name="category">${Object.entries(CATEGORY_LABELS).map(([k, l]) => `<option value="${k}">${l}</option>`).join("")}</select>
    </div>
    <div class="field"><label>Затронутые меры (МОБП)</label><div class="checklist">${controlOptions()}</div></div>
    <div class="field"><label>Экспертная оценка влияния на риск</label>
      <div class="range-row"><input type="range" name="impact" min="0" max="1" step="0.05" value="0.5"><span class="range-val" data-out="impact">0.5</span></div>
    </div>
    <div class="field"><label>Примечания (необязательно)</label><textarea name="notes"></textarea></div>
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" id="ch-cancel">Отмена</button>
      <button type="submit" class="btn btn-primary">Добавить изменение</button>
    </div>
  </form>`);
  wireRangeOutputs(body);
  body.querySelector("#ch-cancel").addEventListener("click", closeModal);
  body.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const controls = Array.from(e.target.querySelectorAll('input[name="controls"]:checked')).map((i) => i.value);
    try {
      await api(`/api/versions/${v.id}/changes`, "POST", {
        description: fd.get("description"), category: fd.get("category"),
        controls, impact: parseFloat(fd.get("impact")), notes: fd.get("notes"),
      });
      toast("Изменение добавлено");
      closeModal();
      await refresh();
    } catch (err) { fail(err); }
  });
  openModal(`Новое изменение — версия «${v.label}»`, body);
}

function renderControlsExecutionCard(v) {
  const controls = STATE.data.controls || [];
  const execByControl = {};
  v.executions.forEach((e) => { execByControl[e.control_id] = e; });

  const card = el(`<div class="card">
    <div class="card-head"><h2>Меры и их выполнение для этой версии</h2></div>
    <div class="table-wrap" id="exec-table"></div>
  </div>`);
  const tableWrap = card.querySelector("#exec-table");

  if (!controls.length) {
    tableWrap.appendChild(el(`<div class="empty-state">Сначала добавьте меры на вкладке «Обзор и МОБП».</div>`));
    return card;
  }

  const rows = controls.map((c) => {
    const exe = execByControl[c.id];
    let statusBadge = '<span class="badge badge-neutral">не начато</span>';
    if (exe) {
      let cls = "badge-neutral";
      if (exe.status === "executed") cls = exe.outcome === "pass" ? "badge-success" : "badge-danger";
      else if (exe.status === "predicted") cls = exe.outcome === "pass" ? "badge-success" : "badge-warning";
      statusBadge = `<span class="badge ${cls}">${STATUS_LABELS[exe.status]}${exe.status !== "planned" ? " · " + OUTCOME_LABELS[exe.outcome] : ""}</span>`;
    }
    return `<tr>
      <td><b>${esc(c.name)}</b> ${c.critical ? '<span class="badge badge-danger">крит.</span>' : ""}</td>
      <td>${statusBadge}</td>
      <td class="faint">${exe ? esc(exe.evidence || "") : ""}</td>
      <td>
        <div class="control-row-actions">
          <button class="btn btn-secondary btn-small" data-exec="${c.id}">Выполнить фактически</button>
          ${!v.is_reference ? `<button class="btn btn-secondary btn-small" data-pasr="${c.id}">Подготовить ПОБП</button>` : ""}
        </div>
      </td>
    </tr>`;
  }).join("");

  tableWrap.appendChild(el(`<table class="table">
    <thead><tr><th>Мера</th><th>Статус</th><th>Свидетельство</th><th>Действия</th></tr></thead>
    <tbody>${rows}</tbody></table>`));

  tableWrap.querySelectorAll("[data-exec]").forEach((btn) => {
    btn.addEventListener("click", () => openExecuteModal(v, controlById(btn.dataset.exec)));
  });
  tableWrap.querySelectorAll("[data-pasr]").forEach((btn) => {
    btn.addEventListener("click", () => openPasrModal(v, controlById(btn.dataset.pasr)));
  });

  return card;
}

function openExecuteModal(v, ctrl) {
  const body = el(`<form id="form-exec">
    <p class="card-sub" style="margin-top:0;">Мера «${esc(ctrl.name)}», версия «${esc(v.label)}»</p>
    <div class="field"><label>Результат</label>
      <select name="outcome"><option value="pass">PASS — соответствует</option><option value="fail">FAIL — не соответствует</option></select>
    </div>
    <div class="field"><label>Свидетельство / артефакт проверки</label><input type="text" name="evidence" required placeholder="Например, «Отчёт SAST-сканирования от 12.03.2026»"></div>
    <div class="field"><label>Кем выполнено</label>${actorFieldHTML("by", "Проектная команда")}</div>
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" id="ex-cancel">Отмена</button>
      <button type="submit" class="btn btn-primary">Зафиксировать выполнение</button>
    </div>
  </form>`);
  wireCustomSelects(body);
  body.querySelector("#ex-cancel").addEventListener("click", closeModal);
  body.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api(`/api/versions/${v.id}/execute`, "POST", {
        control_id: ctrl.id, outcome: fd.get("outcome"), evidence: fd.get("evidence"), by: resolveField(e.target, "by"),
      });
      toast(res.message);
      closeModal();
      await refresh();
    } catch (err) { fail(err); }
  });
  openModal("Шаг 7 — выполнение меры фактически", body);
}

function openPasrModal(v, ctrl) {
  const body = el(`<form id="form-pasr">
    <p class="card-sub" style="margin-top:0;">Мера «${esc(ctrl.name)}», версия «${esc(v.label)}» — перенос доверия через ПОБП (раздел 9). Если изменения, затрагивающие эту меру, признаны существенными — подготовка будет отклонена (раздел 7).</p>
    <div class="form-row">
      <div class="field"><label>Инициатор</label>${actorFieldHTML("initiator", "Проектная команда")}</div>
      <div class="field"><label>Представитель НСО</label>${actorFieldHTML("onf", "Группа НСО")}</div>
    </div>
    <div class="field"><label>Владелец приложения</label>${actorFieldHTML("owner", STATE.data.application.owner)}</div>
    <div class="field"><label>2/3. Обстоятельства прогнозирования</label><textarea name="circumstances" required placeholder="При каких условиях и почему предлагается перенос доверия"></textarea></div>
    <div class="field"><label>4. Обоснование</label><textarea name="rationale" required placeholder="Почему перенос доверия оправдан для данной меры"></textarea></div>
    <div class="field"><label>6. Критерии достаточности обоснования</label><textarea name="criteria" required placeholder="По каким критериям обоснование считается достаточным"></textarea></div>
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" id="pa-cancel">Отмена</button>
      <button type="submit" class="btn btn-primary">Подготовить ПОБП</button>
    </div>
  </form>`);
  wireCustomSelects(body);
  body.querySelector("#pa-cancel").addEventListener("click", closeModal);
  body.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api("/api/pasr", "POST", {
        version_id: v.id, control_id: ctrl.id,
        initiator: resolveField(e.target, "initiator"), onf: resolveField(e.target, "onf"), owner: resolveField(e.target, "owner"),
        circumstances: fd.get("circumstances"), rationale: fd.get("rationale"), criteria: fd.get("criteria"),
      });
      toast(res.message);
      closeModal();
      await refresh();
    } catch (err) { fail(err); }
  });
  openModal("Шаг 4 — подготовка ПОБП", body);
}

function renderPasrCard(v) {
  const card = el(`<div class="card"><div class="card-head"><h2>Прогнозные обоснования безопасности приложения (ПОБП)</h2></div><div id="pasr-list"></div></div>`);
  const list = card.querySelector("#pasr-list");
  if (!v.pasrs.length) {
    list.appendChild(el(`<div class="empty-state"><div class="big">&#128196;</div>Для этой версии ПОБП ещё не готовились.</div>`));
    return card;
  }
  v.pasrs.forEach((p) => list.appendChild(renderPasrItem(v, p)));
  return card;
}

function renderPasrItem(v, p) {
  const statusBadge = p.is_approved
    ? '<span class="badge badge-success">УТВЕРЖДЕНО</span>'
    : (p.is_rejected ? '<span class="badge badge-danger">ОТКЛОНЕНО</span>' : '<span class="badge badge-warning">ОЖИДАЕТ</span>');
  const substBadge = p.substantiality_label
    ? `<span class="badge ${SUBST_BADGE[p.substantiality_label]}">${SUBST_LABELS[p.substantiality_label]} (score=${p.substantiality_score})</span>`
    : "";

  const card = el(`<div class="pasr-card">
    <div class="pasr-head">
      <div>
        <b>${esc(p.control_name)}</b>
        <div class="pasr-id">ПОБП ${p.id} · создан ${fmtDate(p.created_at)}</div>
      </div>
      <div class="pill-row">${statusBadge} ${substBadge}</div>
    </div>
    <div class="pasr-components">
      <div class="row"><b>1. Идентификаторы</b><span>${esc(p.identifiers)}</span></div>
      <div class="row"><b>2. Действующие лица</b><span>инициатор=${esc(p.actors.initiator)}, НСО=${esc(p.actors.onf_group)}, владелец=${esc(p.actors.app_owner)}</span></div>
      <div class="row"><b>3. Обстоятельства</b><span>${esc(p.circumstances)}</span></div>
      <div class="row"><b>4. Обоснование</b><span>${esc(p.rationale)}</span></div>
      <div class="row"><b>5. Результаты исходных МОБП</b><span>${esc(p.original_execution_ref)}</span></div>
      <div class="row"><b>6. Критерии достаточности</b><span>${esc(p.criteria)}</span></div>
    </div>
    <div class="pasr-decisions">
      ${renderDecisionBox(p, "onf", "Группа НСО")}
      ${renderDecisionBox(p, "owner", "Владелец приложения")}
    </div>
  </div>`);

  ["onf", "owner"].forEach((party) => {
    const form = card.querySelector(`form[data-party="${party}"]`);
    if (!form) return;
    wireCustomSelects(form);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        const res = await api(`/api/pasr/${p.id}/decide`, "POST", {
          party, decision: e.submitter.dataset.decision,
          actor: resolveField(e.target, "actor"), justification: fd.get("justification"),
        });
        toast(res.message);
        await refresh();
      } catch (err) { fail(err); }
    });
  });

  return card;
}

function renderDecisionBox(p, party, label) {
  const decision = party === "onf" ? p.onf_decision : p.owner_decision;
  const justification = party === "onf" ? p.onf_justification : p.owner_justification;
  const done = decision !== "pending";
  const cls = decision === "approved" ? "badge-success" : (decision === "rejected" ? "badge-danger" : "badge-warning");
  return `<div class="decision-box">
    <h4>${label} <span class="badge ${cls}" style="float:right;">${DECISION_LABELS[decision]}</span></h4>
    ${done
      ? `<div class="faint">${esc(justification || "без обоснования")}</div>`
      : `<form data-party="${party}">
          <div class="field" style="margin-bottom:6px;">${actorFieldHTML("actor", label, "Кто принимает решение")}</div>
          <div class="field" style="margin-bottom:6px;"><input type="text" name="justification" placeholder="Обоснование решения"></div>
          <div class="decision-row">
            <button type="submit" class="btn btn-primary btn-small" data-decision="approved">Утвердить</button>
            <button type="submit" class="btn btn-danger btn-small" data-decision="rejected">Отклонить</button>
          </div>
        </form>`}
  </div>`;
}

function renderProcessActionsCard(v) {
  const approvedControlIds = v.pasrs.filter((p) => p.is_approved).map((p) => p.control_id);
  const card = el(`<div class="card">
    <div class="card-head"><h2>Шаги 8&ndash;10 &middot; Верификация, аудит, отчёт</h2></div>
    <div class="grid-3">
      <div>
        <h3>8. Верификация выборкой</h3>
        <form id="form-verify">
          <div class="field"><label>Актор</label>${actorFieldHTML("actor", "Аудитор")}</div>
          <div class="field"><label>Доля выборки (кроме критических — берутся всегда)</label>
            <div class="range-row"><input type="range" name="sampling_rate" min="0" max="1" step="0.05" value="0.34"><span class="range-val" data-out="sampling_rate">0.34</span></div>
          </div>
          <div class="field"><label>Seed генератора выборки</label><input type="number" name="seed" value="42"></div>
          ${approvedControlIds.length ? `<div class="field"><label>Смоделировать расхождение для мер</label><div class="checklist"></div></div>` : ""}
          <button type="submit" class="btn btn-secondary btn-block">Запустить верификацию</button>
        </form>
      </div>
      <div>
        <h3>9. Аудит ПОБП</h3>
        <p class="faint">Проверка качества оформления ПОБП и завершённости утверждения, сверка с результатами верификации.</p>
        <form id="form-audit">
          <div class="field"><label>Актор</label>${actorFieldHTML("actor", "Аудитор")}</div>
          <button type="submit" class="btn btn-secondary btn-block">Провести аудит</button>
        </form>
        <div id="audit-result"></div>
      </div>
      <div>
        <h3>10. Оценка и отчёт</h3>
        <p class="faint">Фиксация ожидаемого уровня доверия версии и формирование итогового отчёта (раздел 13).</p>
        <form id="form-assess">
          <div class="field"><label>Актор</label>${actorFieldHTML("actor", "Аудитор")}</div>
          <button type="submit" class="btn btn-secondary btn-block">Зафиксировать оценку</button>
        </form>
        <p class="faint" style="margin-top:8px;">Отчёт формируется кнопкой «Получить отчёт» вверху страницы.</p>
      </div>
    </div>
  </div>`);

  wireRangeOutputs(card);
  wireCustomSelects(card);

  const verifyChecklist = card.querySelector("#form-verify .checklist");
  if (verifyChecklist) {
    verifyChecklist.innerHTML = approvedControlIds.map((cid) => {
      const c = controlById(cid);
      return `<label><input type="checkbox" name="mismatch" value="${cid}"> ${esc(c ? c.name : cid)}</label>`;
    }).join("");
  }

  card.querySelector("#form-verify").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const mismatch = Array.from(e.target.querySelectorAll('input[name="mismatch"]:checked')).map((i) => i.value);
    try {
      const res = await api(`/api/versions/${v.id}/verify`, "POST", {
        actor: resolveField(e.target, "actor"), sampling_rate: parseFloat(fd.get("sampling_rate")),
        seed: fd.get("seed"), mismatch,
      });
      toast(res.message);
      await refresh();
    } catch (err) { fail(err); }
  });

  card.querySelector("#form-audit").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api(`/api/versions/${v.id}/audit`, "POST", { actor: resolveField(e.target, "actor") });
      toast(res.message);
      const s = res.summary;
      card.querySelector("#audit-result").innerHTML = `
        <div class="hr"></div>
        <div class="kv" style="font-size:12.8px;"><b>Вердикт:</b> <span class="badge ${s.verdict === "ПРИНЯТО" ? "badge-success" : "badge-warning"}">${s.verdict}</span></div>
        <div class="faint" style="margin-top:6px;">ПОБП: ${s.pasr_total} (без замечаний: ${s.pasr_quality_ok}, с замечаниями: ${s.pasr_quality_issues})<br>Верификаций: ${s.verification_total} (совпало: ${s.verification_matches}, расхождений: ${s.verification_mismatches})</div>`;
      await refresh();
    } catch (err) { fail(err); }
  });

  card.querySelector("#form-assess").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api(`/api/versions/${v.id}/assess`, "POST", { actor: resolveField(e.target, "actor") });
      toast(res.message);
      await refresh();
    } catch (err) { fail(err); }
  });

  return card;
}

/* ------------------------------------------------------------------ report */

async function openReportModal(v) {
  const body = el(`<div>
    <div class="pill-row" style="margin-bottom:14px;">
      <button class="btn btn-primary btn-small" id="rep-pdf">&#8659; Скачать PDF</button>
      <button class="btn btn-secondary btn-small" id="rep-md">&#8659; Скачать .md</button>
      <button class="btn btn-secondary btn-small" id="rep-close">Закрыть</button>
    </div>
    <div class="report-view" id="rep-body"><div class="empty-state">Формирование отчёта…</div></div>
  </div>`);
  body.querySelector("#rep-close").addEventListener("click", closeModal);
  const pdfName = `report_${v.label}.pdf`.replace(/\s+/g, "_");
  const mdName = `report_${v.label}.md`.replace(/\s+/g, "_");
  body.querySelector("#rep-pdf").addEventListener("click", (e) => downloadFile(`/api/versions/${v.id}/report.pdf`, pdfName, e.currentTarget));
  body.querySelector("#rep-md").addEventListener("click", (e) => downloadFile(`/api/versions/${v.id}/report?download=1`, mdName, e.currentTarget));
  openModal(`Отчёт об ожидаемом уровне доверия — «${v.label}»`, body);
  document.querySelector(".modal").style.maxWidth = "820px";
  try {
    const res = await api(`/api/versions/${v.id}/report`);
    document.getElementById("rep-body").innerHTML = markdownToHtml(res.markdown);
  } catch (err) {
    document.getElementById("rep-body").innerHTML = `<p class="muted">Не удалось сформировать отчёт: ${esc(err.message)}</p>`;
  }
}

function markdownToHtml(md) {
  const lines = md.split("\n");
  let html = "";
  let inCode = false, inList = false, tableRows = [];

  function flushTable() {
    if (!tableRows.length) return;
    const rows = tableRows.filter((r) => !/^\|\s*-{2,}/.test(r.replace(/\|/g, "|")));
    const cellsOf = (r) => r.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
    const isSep = (r) => /^[\s|:-]+$/.test(r) && r.includes("-");
    const dataRows = rows.filter((r) => !isSep(r));
    if (!dataRows.length) { tableRows = []; return; }
    const head = cellsOf(dataRows[0]);
    const body = dataRows.slice(1).map(cellsOf);
    html += "<table><thead><tr>" + head.map((h) => `<th>${inline(h)}</th>`).join("") + "</tr></thead><tbody>";
    body.forEach((r) => { html += "<tr>" + r.map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>"; });
    html += "</tbody></table>";
    tableRows = [];
  }
  function inline(s) {
    return esc(s)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
  }

  for (const raw of lines) {
    const line = raw;
    if (line.trim().startsWith("```")) {
      if (!inCode) { flushTable(); html += "<pre>"; inCode = true; }
      else { html += "</pre>"; inCode = false; }
      continue;
    }
    if (inCode) { html += esc(line) + "\n"; continue; }

    if (line.trim().startsWith("|")) { tableRows.push(line); continue; }
    flushTable();

    if (/^#\s+/.test(line)) { html += `<h1>${inline(line.replace(/^#\s+/, ""))}</h1>`; continue; }
    if (/^##\s+/.test(line)) { html += `<h2>${inline(line.replace(/^##\s+/, ""))}</h2>`; continue; }
    if (/^###\s+/.test(line)) { html += `<h3>${inline(line.replace(/^###\s+/, ""))}</h3>`; continue; }

    if (/^-\s+/.test(line)) {
      if (!inList) { html += "<ul>"; inList = true; }
      html += `<li>${inline(line.replace(/^-\s+/, ""))}</li>`;
      continue;
    } else if (inList) { html += "</ul>"; inList = false; }

    if (!line.trim()) { continue; }
    html += `<p>${inline(line)}</p>`;
  }
  flushTable();
  if (inList) html += "</ul>";
  if (inCode) html += "</pre>";
  return html;
}

/* ------------------------------------------------------------- версии/демо */

function openNewVersionModal() {
  const versions = STATE.data.versions || [];
  const body = el(`<form id="form-version">
    <div class="field"><label>Метка версии</label><input type="text" name="label" required placeholder="Например, «1.1»"></div>
    <div class="field"><label>Эталонная (родительская) версия</label>
      <select name="parent">
        <option value="">&mdash; нет (это эталонная версия) &mdash;</option>
        ${versions.map((v) => `<option value="${v.id}">${esc(v.label)}</option>`).join("")}
      </select>
    </div>
    <div class="field"><label>Целевой уровень доверия</label>
      <div class="range-row"><input type="range" name="target" min="0" max="1" step="0.05" value="0.9"><span class="range-val" data-out="target">0.9</span></div>
    </div>
    <div class="form-actions">
      <button type="button" class="btn btn-secondary" id="ver-cancel">Отмена</button>
      <button type="submit" class="btn btn-primary">Создать версию</button>
    </div>
  </form>`);
  wireRangeOutputs(body);
  body.querySelector("#ver-cancel").addEventListener("click", closeModal);
  body.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/versions", "POST", {
        label: fd.get("label"), parent: fd.get("parent") || null, target: parseFloat(fd.get("target")),
      });
      toast("Версия создана");
      closeModal();
      await refresh();
    } catch (err) { fail(err); }
  });
  openModal("Новая версия приложения", body);
}

async function runDemo() {
  try {
    await api("/api/demo", "POST", {});
    toast("Демо-сценарий загружен");
    STATE.view = "overview";
    STATE.versionId = null;
    await refresh();
  } catch (err) { fail(err); }
}

/* --------------------------------------------------------------- утилиты */

function wireRangeOutputs(root) {
  root.querySelectorAll('input[type="range"]').forEach((r) => {
    const out = root.querySelector(`[data-out="${r.name}"]`);
    if (!out) return;
    const update = () => { out.textContent = r.value; };
    r.addEventListener("input", update);
    update();
  });
}

/* ------------------------------------------------------------------- init */

function wireStaticUi() {
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.addEventListener("click", () => goto(b.dataset.nav));
  });
  document.getElementById("btn-new-version").addEventListener("click", () => {
    if (!STATE.data.application) { toast("Сначала создайте приложение", true); return; }
    openNewVersionModal();
  });
  document.getElementById("btn-demo").addEventListener("click", runDemo);
  document.getElementById("btn-export").addEventListener("click", () => {
    window.open("/api/export", "_blank");
  });
  document.getElementById("btn-back-own").addEventListener("click", async () => {
    try {
      await api("/api/switch", "POST", { which: "own" });
      await refresh();
    } catch (err) { fail(err); }
  });
  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("modal-backdrop").addEventListener("click", (e) => {
    if (e.target.id === "modal-backdrop") closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
}

wireStaticUi();
loadAll().catch(fail);
