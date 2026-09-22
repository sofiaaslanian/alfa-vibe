import { getJSON, esc, parsePrometheus } from "./shared.js";

function statusClass(s) {
  if (s === "measured") return "pd-dot--ok";
  if (s === "partial") return "pd-dot--partial";
  return "pd-dot--bad";
}

async function loadEvidence() {
  const [evidence, ready, metricsText] = await Promise.all([
    getJSON("/demo/evidence"),
    getJSON("/ready").catch(() => ({ status: "down" })),
    fetch("/metrics").then((r) => r.text()),
  ]);

  const live = parsePrometheus(metricsText);
  document.getElementById("kpi-ready").textContent = ready.status || "—";
  document.getElementById("kpi-requests").textContent = String(live.process_total);
  document.getElementById("kpi-latency").textContent =
    live.avg_latency_ms != null ? `${live.avg_latency_ms.toFixed(1)} ms` : "—";
  document.getElementById("kpi-tokens").textContent = String(Math.round(live.tokens));

  const acc = evidence.acceptance;
  const accEl = document.getElementById("acceptance");
  if (!acc) {
    accEl.innerHTML = `<h2 class="pd-card__title">Correctness</h2><p class="pd-status">Нет acceptance_summary.json</p>`;
  } else {
    accEl.innerHTML = `
      <h2 class="pd-card__title">Correctness — 68 acceptance</h2>
      <div class="pd-kpi__value">${acc.cases_passed}/${acc.cases_total}
        <span style="font-size:16px;color:var(--alfa-text-secondary);font-weight:500">
          (${((acc.case_pass_rate || 0) * 100).toFixed(0)}%)
        </span>
      </div>
      <p class="pd-status">span F1=${acc.span_metrics?.f1 ?? "—"} · mask=${acc.mask_accuracy ?? "—"} · round-trip=${acc.roundtrip_rate ?? "—"}</p>
      <table class="table"><thead><tr><th>Тип</th><th>Pass</th><th>F1</th></tr></thead>
      <tbody>
        ${Object.entries(acc.by_type || {})
          .map(
            ([t, v]) =>
              `<tr><td>${esc(t)}</td><td>${v.passed}/${v.cases}</td><td>${v.f1 ?? "—"}</td></tr>`
          )
          .join("")}
      </tbody></table>`;
  }

  document.getElementById("holdout").textContent =
    `Holdout cases: ${evidence.holdout?.cases ?? 0} · ${evidence.holdout?.note || ""}`;

  const load = evidence.load;
  const loadEl = document.getElementById("load");
  if (!load?.profiles) {
    loadEl.innerHTML = `<h2 class="pd-card__title">Load</h2><p class="pd-status">Нет load_results.json</p>`;
  } else {
    loadEl.innerHTML = `
      <h2 class="pd-card__title">Load profiles</h2>
      <p class="pd-status">Цель: RPS≥${load.targets?.rps} · p95≤${load.targets?.p95_ms} ms. ${esc(load.note || "")}</p>
      <table class="table"><thead><tr><th>Профиль</th><th>Host</th><th>RPS</th><th>p95</th><th>Status</th></tr></thead>
      <tbody>
        ${load.profiles
          .map((p) => {
            const st = p.status || (p.rps != null ? "ok" : "—");
            return `<tr>
              <td>${esc(p.name)}</td>
              <td>${esc(p.host)}</td>
              <td>${p.rps != null ? p.rps : "—"}</td>
              <td>${p.p95_ms != null ? p.p95_ms + " ms" : "—"}</td>
              <td>${esc(st)}</td>
            </tr>`;
          })
          .join("")}
      </tbody></table>`;
  }

  const crit = evidence.criteria;
  const critEl = document.getElementById("criteria");
  if (!crit?.criteria) {
    critEl.innerHTML = `<h2 class="pd-card__title">Criteria</h2><p class="pd-status">Нет criteria_checklist.json</p>`;
  } else {
    const rows = crit.criteria
      .map(
        (c) => `<tr>
        <td><span class="pd-dot ${statusClass(c.status)}"></span>${esc(c.id)} ${esc(c.title)}</td>
        <td>${esc(c.status)}</td>
        <td>${esc(c.evidence)}</td>
        <td>${c.team_estimate}/${c.max}</td>
      </tr>`
      )
      .join("");
    const sum = crit.criteria.reduce((a, c) => a + (c.team_estimate || 0), 0);
    const max = crit.criteria.reduce((a, c) => a + (c.max || 0), 0);
    critEl.innerHTML = `
      <h2 class="pd-card__title">Criteria map (3.1–3.8)</h2>
      <table class="table"><thead><tr><th>Критерий</th><th>Статус</th><th>Доказательство</th><th>Оценка команды</th></tr></thead>
      <tbody>${rows}</tbody></table>
      <p class="hint" style="margin-top:12px">${esc(crit.disclaimer)} Сумма: <strong>${sum}/${max}</strong> — не балл жюри.</p>`;
  }
}

loadEvidence().catch((e) => {
  document.getElementById("acceptance").textContent = e.message;
});
