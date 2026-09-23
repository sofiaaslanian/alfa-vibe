import { getJSON, esc, parsePrometheus } from "./shared.js";

function statusClass(s) {
  if (s === "measured") return "pd-dot--ok";
  if (s === "partial") return "pd-dot--partial";
  return "pd-dot--bad";
}

function renderEvidenceKpis(evidence, ready, live) {
  document.getElementById("kpi-ready").textContent = ready.status || "—";
  document.getElementById("kpi-requests").textContent = String(live.process_total);
  document.getElementById("kpi-latency").textContent =
    live.avg_latency_ms != null ? `${live.avg_latency_ms.toFixed(1)} ms` : "—";
  document.getElementById("kpi-tokens").textContent = String(Math.round(live.tokens));
  document.getElementById("holdout").textContent =
    `Holdout cases: ${evidence.holdout?.cases ?? 0} · ${evidence.holdout?.note || ""}`;
}

function loadProfileRow(profile) {
  const status = profile.status || (profile.rps != null ? "ok" : "—");
  return `<tr>
    <td>${esc(profile.name)}</td>
    <td>${esc(profile.host)}</td>
    <td>${profile.rps != null ? profile.rps : "—"}</td>
    <td>${profile.p95_ms != null ? profile.p95_ms + " ms" : "—"}</td>
    <td>${esc(status)}</td>
  </tr>`;
}

function renderLoad(load) {
  const loadEl = document.getElementById("load");
  if (!load?.profiles) {
    loadEl.innerHTML = `<h2 class="pd-card__title">Load</h2><p class="pd-status">Нет load_results.json</p>`;
    return;
  }
  const rows = load.profiles.map(loadProfileRow).join("");
  loadEl.innerHTML = `
    <h2 class="pd-card__title">Load profiles</h2>
    <p class="pd-status">Цель: RPS≥${load.targets?.rps} · p95≤${load.targets?.p95_ms} ms. ${esc(load.note || "")}</p>
    <table class="table"><thead><tr><th>Профиль</th><th>Host</th><th>RPS</th><th>p95</th><th>Status</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function criteriaRow(criterion) {
  return `<tr>
    <td><span class="pd-dot ${statusClass(criterion.status)}"></span>${esc(criterion.id)} ${esc(criterion.title)}</td>
    <td>${esc(criterion.status)}</td>
    <td>${esc(criterion.evidence)}</td>
    <td>${criterion.team_estimate}/${criterion.max}</td>
  </tr>`;
}

function renderCriteria(criteria) {
  const critEl = document.getElementById("criteria");
  if (!criteria?.criteria) {
    critEl.innerHTML = `<h2 class="pd-card__title">Criteria</h2><p class="pd-status">Нет criteria_checklist.json</p>`;
    return;
  }
  const rows = criteria.criteria.map(criteriaRow).join("");
  const sum = criteria.criteria.reduce((a, c) => a + (c.team_estimate || 0), 0);
  const max = criteria.criteria.reduce((a, c) => a + (c.max || 0), 0);
  critEl.innerHTML = `
    <h2 class="pd-card__title">Criteria map (3.1–3.8)</h2>
    <table class="table"><thead><tr><th>Критерий</th><th>Статус</th><th>Доказательство</th><th>Оценка команды</th></tr></thead>
    <tbody>${rows}</tbody></table>
    <p class="hint" style="margin-top:12px">${esc(criteria.disclaimer)} Сумма: <strong>${sum}/${max}</strong> — не балл жюри.</p>`;
}

async function loadEvidence() {
  const [evidence, ready, metricsText] = await Promise.all([
    getJSON("/demo/evidence"),
    getJSON("/ready").catch(() => ({ status: "down" })),
    fetch("/metrics").then((response) => response.text()),
  ]);
  const live = parsePrometheus(metricsText);
  renderEvidenceKpis(evidence, ready, live);
  renderLoad(evidence.load);
  renderCriteria(evidence.criteria);
}

await loadEvidence();
