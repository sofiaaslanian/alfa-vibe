/* Shared helpers for Contour + Evidence */
export function apiKey() {
  return localStorage.getItem("alfa_proxy_key") || "";
}

export function headers(system) {
  return {
    "Content-Type": "application/json",
    "X-API-Key": apiKey(),
    "X-System": system || "demo",
    "X-Consumer-Id": "demo-ui",
  };
}

export async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} → ${r.status}`);
  return r.json();
}

export function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

const PROM_METRICS = [
  ["alfa_process_total{", "process_total"],
  ["alfa_process_latency_seconds_sum", "latency_sum"],
  ["alfa_process_latency_seconds_count", "latency_count"],
  ["alfa_tokens_total{", "tokens"],
];

function prometheusMetric(line) {
  return PROM_METRICS.find(([prefix]) => line.startsWith(prefix));
}

export function parsePrometheus(text) {
  const out = { process_total: 0, latency_sum: 0, latency_count: 0, tokens: 0 };
  for (const line of text.split("\n")) {
    if (line.startsWith("#") || !line.trim()) continue;
    const metric = prometheusMetric(line);
    if (!metric) continue;
    const value = Number(line.split(" ").pop());
    if (!Number.isNaN(value)) out[metric[1]] += value;
  }
  out.avg_latency_ms =
    out.latency_count > 0 ? (out.latency_sum / out.latency_count) * 1000 : null;
  return out;
}
