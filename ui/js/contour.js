import { apiKey, headers, getJSON, esc } from "./shared.js";

const SCENARIOS = [
  {
    id: "fio_email",
    label: "ФИО + email",
    text: "Клиент Иванов Иван Иванович просит ответ на ivanov@mail.ru",
  },
  {
    id: "passport",
    label: "Паспорт",
    text: "Паспорт клиента: серия 4510, номер 123456. Выдан ГУ МВД России по г. Москве",
  },
  {
    id: "pushkin",
    label: "Ловушка Пушкин",
    text: "Александр Пушкин — русский поэт",
  },
  {
    id: "bank_addr",
    label: "Адрес банка",
    text: "Адрес отделения Банка: Москва, ул. Тверская, д. 10",
  },
  {
    id: "card",
    label: "Карта",
    text: "Держатель карты: IVAN IVANOV, карта 4111 1111 1111 1111, CVV 123",
  },
  {
    id: "client_addr",
    label: "Адрес клиента",
    text: "Адрес проживания клиента: Москва, ул. Тверская, д. 10, кв. 15",
  },
];

const els = {
  system: document.getElementById("system"),
  input: document.getElementById("input"),
  chips: document.getElementById("chips"),
  run: document.getElementById("run"),
  skipLlm: document.getElementById("skip-llm"),
  status: document.getElementById("status"),
  findings: document.getElementById("findings"),
  masked: document.getElementById("masked"),
  llmWire: document.getElementById("llm-wire"),
  answer: document.getElementById("answer"),
  restored: document.getElementById("restored"),
  originalCompare: document.getElementById("original-compare"),
  leakBadge: document.getElementById("leak-badge"),
  stages: {
    detect: document.getElementById("stage-detect"),
    mask: document.getElementById("stage-mask"),
    state: document.getElementById("stage-state"),
    llm: document.getElementById("stage-llm"),
    demask: document.getElementById("stage-demask"),
  },
};

function setStage(name, on, ms) {
  const el = els.stages[name];
  if (!el) return;
  el.classList.toggle("is-on", !!on);
  const msEl = el.querySelector(".pd-stage__ms");
  if (msEl) msEl.textContent = ms != null ? `${ms} ms` : "—";
}

function resetStages() {
  Object.keys(els.stages).forEach((k) => setStage(k, false, null));
  els.findings.innerHTML = "";
  els.masked.textContent = "";
  if (els.llmWire) els.llmWire.textContent = "";
  els.answer.textContent = "";
  els.restored.textContent = "";
  els.originalCompare.textContent = "";
  els.leakBadge.className = "badge badge--warn";
  els.leakBadge.textContent = "ожидание прогона";
}

async function loadSystems() {
  const cfg = await getJSON("/demo/config");
  els.system.innerHTML = "";
  for (const [name, s] of Object.entries(cfg.systems || {})) {
    if (["disabled_example", "autotest"].includes(name)) continue;
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = `${name} · demask=${s.allow_demask ? "yes" : "no"} · ${s.mask_style}`;
    if (name === "demo") opt.selected = true;
    els.system.appendChild(opt);
  }
}

function renderChips() {
  els.chips.innerHTML = "";
  SCENARIOS.forEach((s, i) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "pd-chip" + (i === 0 ? " is-active" : "");
    b.textContent = s.label;
    b.addEventListener("click", () => {
      els.chips.querySelectorAll(".pd-chip").forEach((c) => c.classList.remove("is-active"));
      b.classList.add("is-active");
      els.input.value = s.text;
    });
    els.chips.appendChild(b);
  });
  els.input.value = SCENARIOS[0].text;
}

async function run() {
  resetStages();
  els.run.disabled = true;
  els.status.textContent = "прогон контура…";
  const body = {
    text: els.input.value,
    skip_llm: els.skipLlm.checked,
  };
  try {
    const r = await fetch("/demo/run", {
      method: "POST",
      headers: headers(els.system.value),
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || r.statusText);

    const ms = data.stages_ms || {};
    const order = ["detect", "mask", "state", "llm", "demask"];
    for (let i = 0; i < order.length; i++) {
      await new Promise((res) => setTimeout(res, 90));
      setStage(order[i], true, ms[order[i]]);
    }

    els.findings.innerHTML = (data.findings || [])
      .map((f) => `<span class="pd-pill">${esc(f.type)} · ${esc(f.value)}</span>`)
      .join("") || `<span class="pd-status">находок нет</span>`;

    els.masked.textContent = data.masked_prompt || "";
    els.masked.classList.add("pd-flash");
    if (els.llmWire) {
      els.llmWire.textContent = data.masked_prompt || "";
      els.llmWire.classList.add("pd-flash");
    }
    els.answer.textContent = data.answer || "";
    els.restored.textContent = data.restored || "";
    els.originalCompare.textContent = data.original || "";

    if (data.leak_free) {
      els.leakBadge.className = "badge badge--ok";
      els.leakBadge.textContent = "открытых ПД в LLM: 0";
    } else {
      els.leakBadge.className = "badge badge--tag";
      els.leakBadge.textContent = `утечка: ${(data.open_pii_in_llm || []).join(", ")}`;
    }

    const rt = data.roundtrip_ok ? "round-trip OK" : "round-trip check";
    els.status.textContent = `${data.operation_id.slice(0, 8)} · ${data.llm_status} · ${ms.total} ms · ${rt}`;
  } catch (e) {
    els.status.textContent = `ошибка: ${e.message}`;
    els.leakBadge.className = "badge badge--tag";
    els.leakBadge.textContent = "прогон не удался";
  } finally {
    els.run.disabled = false;
  }
}

document.getElementById("api-key").value = apiKey();
document.getElementById("api-key").addEventListener("change", (e) => {
  localStorage.setItem("alfa_proxy_key", e.target.value.trim() || "demo-key");
});

els.run.addEventListener("click", run);
loadSystems().catch((e) => {
  els.status.textContent = `config: ${e.message}`;
});
renderChips();
resetStages();
