import { apiKey, headers, getJSON, esc } from "./shared.js";

const TYPE_RU = {
  PERSON: "ФИО",
  PERSON_NAME: "ФИО",
  EMAIL: "Email",
  PHONE: "Телефон",
  INN: "ИНН",
  PAYMENT_CARD: "Карта",
  CVV: "CVV",
  PIN: "PIN",
  BIRTH_DATE: "Дата рождения",
  PASSPORT: "Паспорт",
  PASSPORT_NUMBER: "Паспорт",
  PASSPORT_ISSUE_DATE: "Дата выдачи",
  PASSPORT_ISSUER: "Кем выдан",
  SUBDIVISION_CODE: "Код подразделения",
  PASSPORT_DIVISION_CODE: "Код подразделения",
  ADDRESS: "Адрес",
  PLACE_OF_BIRTH: "Место рождения",
  CITIZENSHIP: "Гражданство",
  CARDHOLDER_NAME: "Держатель",
  DRIVER_LICENSE: "ВУ",
  DRIVER_LICENSE_NUMBER: "ВУ",
};

const PART_RU = {
  first: "имя",
  middle: "отчество",
  last: "фамилия",
  full: "полное",
  series: "серия",
  number: "номер",
  city: "город",
  street: "улица",
  house: "дом",
  flat: "квартира",
  building: "корпус",
  index: "индекс",
  district: "район",
  region: "регион",
};

const METHOD = (detector = "") => {
  if (/ner|rubert|ml/i.test(detector)) return "ML";
  if (/label|role|called|json/i.test(detector)) return "Role";
  return "Rule";
};

const GROUPS = [
  { id: "basic", label: "Базовые" },
  { id: "context", label: "Контекст" },
  { id: "trap", label: "Ловушки" },
  { id: "killer", label: "Killer" },
];

const SCENARIOS = [
  {
    id: "fio_email",
    group: "basic",
    label: "ФИО + Email",
    verdictKind: "protect",
    text: "Клиент Иванов Иван Иванович просит ответ на ivanov@mail.ru",
  },
  {
    id: "passport_date",
    group: "basic",
    label: "Паспорт + дата",
    verdictKind: "protect",
    text: "Клиент Петров Иван, дата рождения 01.02.1990. Паспорт: серия 45 11, номер 123456; выдан 03.04.2015 ГУ МВД России по г. Москве.",
  },
  {
    id: "card_cvv",
    group: "basic",
    label: "Карта + CVV",
    verdictKind: "protect",
    text: "Держатель карты: IVAN IVANOV, карта 4111 1111 1111 1111, CVV 123",
  },
  {
    id: "client_addr",
    group: "context",
    label: "Адрес клиента",
    verdictKind: "protect_address",
    text: "Адрес проживания клиента: Москва, ул. Тверская, д. 10, кв. 15",
  },
  {
    id: "bank_addr",
    group: "context",
    label: "Адрес банка",
    verdictKind: "allow_service",
    reason:
      "ADDRESS candidate → service context (отделение банка) → ALLOW — служебный адрес не маскируем.",
    text: "Адрес отделения Банка: Москва, ул. Тверская, д. 10",
  },
  {
    id: "pushkin",
    group: "trap",
    label: "Пушкин ≠ ПД",
    verdictKind: "allow_noticed",
    reason:
      "ФИО найдено, но нет клиентского контекста → ALLOW, маскировать не нужно.",
    text: "Александр Пушкин — русский поэт",
  },
  {
    id: "zhirik",
    group: "trap",
    label: "Знаменитость",
    verdictKind: "allow_noticed",
    reason:
      "ФИО распознано · нет KYC/«клиент» · маскировка не нужна.",
    text: "Владимир владимирович Жириновский любит кофе",
  },
  {
    id: "all_in",
    group: "killer",
    label: "Всё сразу",
    verdictKind: "protect",
    text: "Клиент Иван Петров; дата рождения 01.02.1990; тел. +7 (999) 123-45-67; почта ivan@example.ru; ИНН 500100732259; карта 4111 1111 1111 1111; CVV 123. Адрес проживания: Москва, ул. Арбат, д. 10, кв. 2.",
  },
];

let activeScenario = SCENARIOS[0];
let customMode = false;
let lastData = null;
let focusIdx = -1;

const els = {
  groups: document.getElementById("scenario-groups"),
  input: document.getElementById("input"),
  run: document.getElementById("run"),
  skipLlm: document.getElementById("skip-llm"),
  system: document.getElementById("system"),
  consumerLine: document.getElementById("consumer-line"),
  status: document.getElementById("status"),
  verdict: document.getElementById("verdict"),
  verdictTitle: document.getElementById("verdict-title"),
  verdictSub: document.getElementById("verdict-sub"),
  mFound: document.getElementById("m-found"),
  mMasked: document.getElementById("m-masked"),
  mLeak: document.getElementById("m-leak"),
  mMs: document.getElementById("m-ms"),
  latencyDetail: document.getElementById("latency-detail"),
  panelOriginal: document.getElementById("panel-original"),
  panelMasked: document.getElementById("panel-masked"),
  panelRestored: document.getElementById("panel-restored"),
  findList: document.getElementById("find-list"),
  spanTip: document.getElementById("span-tip"),
  leakBadge: document.getElementById("leak-badge"),
  restoreBadge: document.getElementById("restore-badge"),
  xrayNote: document.getElementById("xray-note"),
  xrayBody: document.getElementById("xray-body"),
  xray: document.getElementById("xray"),
};

function typeLabel(t) {
  return TYPE_RU[t] || t;
}

function partLabel(f) {
  if (!f?.part) return "";
  return PART_RU[f.part] || f.part;
}

function typeWithPart(f) {
  const base = typeLabel(f.type);
  const p = partLabel(f);
  return p ? `${base} · ${p}` : base;
}

function protectionMs(ms) {
  const keys = ["detect", "mask", "state", "demask"];
  return keys.reduce((s, k) => s + (Number(ms[k]) || 0), 0);
}

function highlightOriginal(text, findings) {
  if (!findings?.length) return esc(text);
  const ordered = [...findings].sort((a, b) => a.start - b.start);
  let html = "";
  let cursor = 0;
  ordered.forEach((f, i) => {
    if (f.start < cursor) return;
    html += esc(text.slice(cursor, f.start));
    const allow = (f.decision || "mask") === "allow";
    const cls = [
      allow ? "pd-span pd-span--allow" : "pd-span",
      i === focusIdx ? "is-focus" : "",
    ]
      .filter(Boolean)
      .join(" ");
    html += `<mark class="${cls}" data-idx="${i}" tabindex="0">${esc(text.slice(f.start, f.end))}</mark>`;
    cursor = f.end;
  });
  html += esc(text.slice(cursor));
  return html;
}

function highlightMasked(masked) {
  if (!masked) return "";
  let html = esc(masked);
  // scoped tokens ⟦PII_TYPE_hex⟧ or angle <TYPE_n>
  html = html.replace(
    /⟦PII_[A-Z_]+_[0-9a-f]+⟧/gi,
    (m) => `<span class="pd-token">${m}</span>`
  );
  html = html.replace(
    /&lt;([A-Z_]+)_(\d+)&gt;/g,
    '<span class="pd-token">&lt;$1_$2&gt;</span>'
  );
  return html;
}

function setFocus(idx) {
  focusIdx = idx;
  if (!lastData) return;
  const f = lastData.findings[idx];
  els.panelOriginal.innerHTML = highlightOriginal(lastData.original, lastData.findings);
  bindSpanClicks();
  els.findList.querySelectorAll(".pd-find").forEach((el, i) => {
    el.classList.toggle("is-focus", i === idx);
  });
  if (f) {
    const allow = (f.decision || "mask") === "allow";
    const decision = allow ? "ALLOW" : "MASK";
    const why = f.reason ? ` · ${esc(f.reason)}` : "";
    els.spanTip.hidden = false;
    els.spanTip.innerHTML = `<strong>${esc(f.value)}</strong>${esc(typeWithPart(f))} · ${esc(METHOD(f.detector))} · ${esc(f.detector)} · <span class="pd-find__decision${allow ? " pd-find__decision--allow" : ""}">${decision}</span>${why}`;
  }
}

function bindSpanClicks() {
  els.panelOriginal.querySelectorAll(".pd-span").forEach((el) => {
    el.addEventListener("click", () => setFocus(Number(el.dataset.idx)));
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        setFocus(Number(el.dataset.idx));
      }
    });
  });
}

function renderFindingsList(findings) {
  if (!findings.length) {
    els.findList.innerHTML = `<div class="pd-empty">ПД не обнаружены — можно править текст слева и запускать снова</div>`;
    return;
  }
  els.findList.innerHTML = findings
    .map((f, i) => {
      const allow = (f.decision || "mask") === "allow";
      return `<div class="pd-find${i === focusIdx ? " is-focus" : ""}${allow ? " pd-find--allow" : ""}" data-idx="${i}">
        <div class="pd-find__value">${esc(f.value)}</div>
        <div class="pd-find__meta">
          <span>${esc(typeWithPart(f))}</span>
          <span>${esc(METHOD(f.detector))}</span>
          <span>${(f.score * 100).toFixed(0)}%</span>
          <span class="pd-find__decision${allow ? " pd-find__decision--allow" : ""}">${allow ? "ALLOW" : "MASK"}</span>
        </div>
        ${allow && f.reason ? `<div class="pd-find__reason">${esc(f.reason)}</div>` : ""}
      </div>`;
    })
    .join("");
  els.findList.querySelectorAll(".pd-find").forEach((el) => {
    el.addEventListener("click", () => setFocus(Number(el.dataset.idx)));
  });
}

function renderXray(data) {
  const findings = data.findings || [];
  const rows = findings.map((f) => {
    const allow = (f.decision || "mask") === "allow";
    return `<tr>
      <td>${esc(f.value)}</td>
      <td>${esc(typeWithPart(f))}</td>
      <td>${esc(METHOD(f.detector))} · ${esc(f.detector)}</td>
      <td>${(f.score * 100).toFixed(0)}%</td>
      <td>${allow ? "ALLOW" : "MASK"}${f.reason ? ` · ${esc(f.reason)}` : ""}</td>
    </tr>`;
  });
  els.xrayBody.innerHTML =
    rows.join("") || `<tr><td colspan="5">Нет строк решения</td></tr>`;
  els.xrayNote.textContent = activeScenario?.reason || "";
  const kind = resolveKind(data);
  if (kind === "allow_public" || kind === "allow_service" || kind === "allow_noticed") {
    els.xray.open = true;
  }
}

function resolveKind(data) {
  const text = data.original || "";
  const findings = data.findings || [];
  const masked = findings.filter((f) => (f.decision || "mask") === "mask");
  const allowed = findings.filter((f) => f.decision === "allow");
  const n = masked.length;
  if (!customMode && activeScenario?.verdictKind) {
    return activeScenario.verdictKind;
  }
  if (n === 0 && allowed.some((f) => f.type === "PERSON")) return "allow_noticed";
  if (/пушкин/i.test(text) && /поэт/i.test(text) && n === 0) return "allow_public";
  if (/отделен/i.test(text) && /банк/i.test(text) && n === 0) return "allow_service";
  if (/адрес\s+проживани|адрес\s+клиента|мой\s+адрес/i.test(text) && n > 0) {
    return "protect_address";
  }
  return n > 0 ? "protect" : "allow_empty";
}

function setVerdictMask(mode) {
  /* on = masked PII present; off = nothing masked; idle = before run */
  els.verdict.dataset.mask = mode;
}

function verdictSubText(kind, noticedN, maskedN) {
  const messages = {
    allow_public:
      activeScenario?.reason ||
      "0 ПД клиента · 0 ложных срабатываний · в LLM ушёл исходный текст",
    allow_service:
      activeScenario?.reason || "ADDRESS candidate → service context → ALLOW",
    allow_empty: "ПД не обнаружены · в LLM уходит исходный текст без изменений",
    protect_address: `Адрес клиента защищён · ${maskedN} ПД · 0 открытых в LLM`,
  };
  if (kind === "allow_noticed") {
    return noticedN === 1
      ? "ФИО распознано · нет личного контекста клиента · в LLM уходит как есть"
      : `${noticedN} фрагмента распознаны · маскировать не требуется · в LLM уходит как есть`;
  }
  return messages[kind] || `${maskedN} ПД · замаскировано ${maskedN}/${maskedN} · 0 открытых в LLM`;
}

function renderLeak(data) {
  els.verdict.dataset.state = "leak";
  setVerdictMask("on");
  els.verdictTitle.textContent = "Запрос не маскирован";
  els.verdictSub.textContent = `Утечка в LLM: ${(data.open_pii_in_llm || []).join(", ")}`;
}

function renderVerdict(data) {
  const findings = data.findings || [];
  const maskedN = findings.filter((f) => (f.decision || "mask") === "mask").length;
  const noticedN = findings.filter((f) => f.decision === "allow").length;
  const ms = data.stages_ms || {};
  const overhead = protectionMs(ms);
  const leak = (data.open_pii_in_llm || []).length;
  const kind = resolveKind(data);
  const protected_ = maskedN > 0 && leak === 0;

  els.mFound.textContent = String(findings.length);
  els.mMasked.textContent = String(maskedN);
  els.mLeak.textContent = String(leak);
  els.mMs.textContent = `${overhead.toFixed(2)} ms`;
  els.latencyDetail.textContent = `Detect ${ms.detect ?? "—"} · Mask ${ms.mask ?? "—"} · State ${ms.state ?? "—"} · LLM ${ms.llm ?? "—"} · Unmask ${ms.demask ?? "—"} ms`;

  if (leak > 0) {
    renderLeak(data);
    return;
  }

  els.verdict.dataset.state = "ok";
  setVerdictMask(protected_ ? "on" : "off");
  els.verdictTitle.textContent = protected_ ? "Запрос маскирован" : "Запрос не маскирован";
  els.verdictSub.textContent = verdictSubText(kind, noticedN, maskedN);
}

function renderResult(data) {
  lastData = data;
  focusIdx = data.findings?.length ? 0 : -1;
  els.panelOriginal.innerHTML = highlightOriginal(data.original, data.findings);
  els.panelOriginal.classList.add("pd-flash");
  bindSpanClicks();
  renderFindingsList(data.findings || []);
  els.panelMasked.innerHTML = highlightMasked(data.masked_prompt || "");
  els.panelMasked.classList.add("pd-flash");

  if (data.leak_free) {
    els.leakBadge.className = "badge badge--neutral";
    els.leakBadge.textContent = "открытых ПД: 0";
  } else {
    els.leakBadge.className = "badge badge--tag";
    els.leakBadge.textContent = `утечка: ${(data.open_pii_in_llm || []).join(", ")}`;
  }

  const restored = data.restored ?? "";
  els.panelRestored.textContent = restored || data.answer || "";
  const n = (data.findings || []).length;
  if (data.roundtrip_ok) {
    els.restoreBadge.className = "badge badge--neutral";
    els.restoreBadge.textContent = n ? `восстановлено ${n}/${n}` : "без изменений";
  } else if (restored) {
    els.restoreBadge.className = "badge badge--warn";
    els.restoreBadge.textContent = "частично";
  } else {
    els.restoreBadge.className = "badge badge--neutral";
    els.restoreBadge.textContent = "demask off";
  }

  renderVerdict(data);
  renderXray(data);
  if (focusIdx >= 0) setFocus(focusIdx);
}

function resetUI() {
  lastData = null;
  focusIdx = -1;
  els.verdict.dataset.state = "idle";
  setVerdictMask("idle");
  els.verdictTitle.textContent = "Запрос";
  els.verdictSub.textContent =
    "Вставьте любой текст или выберите сценарий — покажем detect → LLM → restore";
  els.mFound.textContent = "—";
  els.mMasked.textContent = "—";
  els.mLeak.textContent = "—";
  els.mMs.textContent = "—";
  els.latencyDetail.textContent = "Detect — · Mask — · State — · LLM — · Unmask —";
  els.panelOriginal.textContent = els.input.value;
  els.panelMasked.textContent = "";
  els.panelRestored.textContent = "";
  els.findList.innerHTML = `<div class="pd-empty">После запуска — список находок</div>`;
  els.spanTip.hidden = true;
  els.leakBadge.className = "badge badge--neutral";
  els.leakBadge.textContent = "ожидание";
  els.restoreBadge.className = "badge badge--neutral";
  els.restoreBadge.textContent = "ожидание";
  els.xrayBody.innerHTML = "";
  els.xrayNote.textContent = "";
}

function selectScenario(s) {
  customMode = false;
  activeScenario = s;
  els.input.value = s.text;
  els.groups.querySelectorAll(".pd-chip").forEach((b) => {
    b.classList.toggle("is-active", b.dataset.id === s.id);
  });
  resetUI();
}

function markCustomEdit() {
  if (activeScenario && els.input.value === activeScenario.text) return;
  customMode = true;
  activeScenario = { id: "custom", group: "custom", label: "Свой текст", verdictKind: null, reason: "" };
  els.groups.querySelectorAll(".pd-chip").forEach((b) => b.classList.remove("is-active"));
}

function renderScenarioGroups() {
  els.groups.innerHTML = "";
  GROUPS.forEach((g) => {
    const items = SCENARIOS.filter((s) => s.group === g.id);
    if (!items.length) return;
    const wrap = document.createElement("div");
    wrap.className = "pd-group";
    wrap.innerHTML = `<div class="pd-group__label">${esc(g.label)}</div>`;
    const chips = document.createElement("div");
    chips.className = "pd-chips";
    items.forEach((s) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "pd-chip" + (s.id === activeScenario.id ? " is-active" : "");
      b.dataset.id = s.id;
      b.textContent = s.label;
      b.addEventListener("click", () => selectScenario(s));
      chips.appendChild(b);
    });
    wrap.appendChild(chips);
    els.groups.appendChild(wrap);
  });
}

function updateConsumerLine() {
  const opt = els.system.selectedOptions[0];
  const name = els.system.value || "demo";
  const demask = opt?.dataset.demask === "1" ? "on" : "off";
  els.consumerLine.textContent = `Consumer: ${name} · demask: ${demask}`;
}

async function loadSystems() {
  const cfg = await getJSON("/demo/config");
  els.system.innerHTML = "";
  for (const [name, s] of Object.entries(cfg.systems || {})) {
    if (["disabled_example", "autotest"].includes(name)) continue;
    const opt = document.createElement("option");
    opt.value = name;
    opt.dataset.demask = s.allow_demask ? "1" : "0";
    opt.textContent = `${name} · demask=${s.allow_demask ? "yes" : "no"} · ${s.mask_style}`;
    if (name === "demo") opt.selected = true;
    els.system.appendChild(opt);
  }
  updateConsumerLine();
}

async function run() {
  resetUI();
  els.run.disabled = true;
  els.status.textContent = "защита запроса…";
  els.panelOriginal.textContent = els.input.value;
  try {
    const r = await fetch("/demo/run", {
      method: "POST",
      headers: headers(els.system.value),
      body: JSON.stringify({
        text: els.input.value,
        skip_llm: els.skipLlm.checked,
      }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || r.statusText);
    renderResult(data);
    const ms = data.stages_ms || {};
    els.status.textContent = `${data.operation_id.slice(0, 8)} · ${data.llm_status} · total ${ms.total} ms`;
  } catch (e) {
    els.status.textContent = `ошибка: ${e.message}`;
    els.verdict.dataset.state = "leak";
    els.verdictTitle.textContent = "Прогон не удался";
    els.verdictSub.textContent = e.message;
  } finally {
    els.run.disabled = false;
  }
}

document.getElementById("api-key").value = apiKey();
document.getElementById("api-key").addEventListener("change", (e) => {
  localStorage.setItem("alfa_proxy_key", e.target.value.trim() || "demo-key");
});
els.system.addEventListener("change", updateConsumerLine);
els.input.addEventListener("input", () => {
  markCustomEdit();
  if (!lastData) els.panelOriginal.textContent = els.input.value;
});
els.run.addEventListener("click", run);

function init() {
  if (!els.groups) {
    console.error("scenario-groups missing");
    return;
  }
  renderScenarioGroups();
  els.input.value = activeScenario.text;
  resetUI();
  loadSystems().catch((e) => {
    els.status.textContent = `config: ${e.message}`;
  });
}

init();
