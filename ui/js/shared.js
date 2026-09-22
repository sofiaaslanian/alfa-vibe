/* Shared helpers for Contour + Evidence */
export function apiKey() {
  return localStorage.getItem("alfa_proxy_key") || "demo-key";
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

export function parsePrometheus(text) {
  const out = { process_total: 0, latency_sum: 0, latency_count: 0, tokens: 0 };
  for (const line of text.split("\n")) {
    if (line.startsWith("#") || !line.trim()) continue;
    if (line.startsWith("alfa_process_total{")) {
      const v = Number(line.split(" ").pop());
      if (!Number.isNaN(v)) out.process_total += v;
    } else if (line.startsWith("alfa_process_latency_seconds_sum")) {
      const v = Number(line.split(" ").pop());
      if (!Number.isNaN(v)) out.latency_sum += v;
    } else if (line.startsWith("alfa_process_latency_seconds_count")) {
      const v = Number(line.split(" ").pop());
      if (!Number.isNaN(v)) out.latency_count += v;
    } else if (line.startsWith("alfa_tokens_total{")) {
      const v = Number(line.split(" ").pop());
      if (!Number.isNaN(v)) out.tokens += v;
    }
  }
  out.avg_latency_ms =
    out.latency_count > 0 ? (out.latency_sum / out.latency_count) * 1000 : null;
  return out;
}
