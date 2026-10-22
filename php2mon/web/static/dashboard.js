"use strict";
const $ = (id) => document.getElementById(id);
const charts = {};

// Draws vertical markers for chart.options.plugins.markers = [{x: ms, label, color}].
const markerPlugin = {
  id: "markers",
  afterDatasetsDraw(chart) {
    const { ctx, chartArea, scales } = chart;
    for (const m of chart.options.plugins.markers || []) {
      const x = scales.x.getPixelForValue(m.x);
      if (x < chartArea.left || x > chartArea.right) continue;
      ctx.save();
      ctx.strokeStyle = m.color;
      ctx.setLineDash([4, 3]);
      ctx.beginPath();
      ctx.moveTo(x, chartArea.top);
      ctx.lineTo(x, chartArea.bottom);
      ctx.stroke();
      ctx.fillStyle = m.color;
      ctx.fillText(m.label, x + 3, chartArea.top + 10 + (m.row || 0) * 12);
      ctx.restore();
    }
  },
};
Chart.register(markerPlugin);

function draw(id, config) {
  if (charts[id]) { charts[id].destroy(); }
  charts[id] = new Chart($(id), config);
}

async function get(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + " " + r.status);
  return r.json();
}

function tile(n, l) {
  const d = document.createElement("div");
  d.className = "tile";
  const a = document.createElement("div"); a.className = "n"; a.textContent = n ?? "-";
  const b = document.createElement("div"); b.className = "l"; b.textContent = l;
  d.append(a, b);
  return d;
}

async function headline() {
  const h = await get("/api/headline");
  $("tiles").replaceChildren(
    tile(h.current_hour_exploit_hits, "exploit-confidence hits this hour"),
    tile(h.exploit_hits_since_patch, "exploit hits since patch release"),
    tile(h.pre_patch_exploit_hits, "exploit hits, 24h before release"),
    tile(h.total_hits_24h, "total hits (24h)"),
    tile(h.unique_ips_24h, "unique IPs (24h)"),
    tile(h.l7_attacks_latest, "Cloudflare Radar L7 attacks"),
  );
}

async function timeline() {
  const t = await get("/api/timeline?window=" + encodeURIComponent($("window").value));
  const a = t.annotations;
  const markers = [{ x: Date.parse(a.patch_release), label: "patch release", color: "#ff5d5d", row: 0 }];
  if (a.embargo) markers.push({ x: Date.parse(a.embargo), label: "embargo lifted", color: "#f0b429", row: 1 });
  if (a.cf_rules) markers.push({ x: Date.parse(a.cf_rules), label: "CF rules", color: "#4cc3ff", row: 2 });
  for (const k of a.kev) markers.push({ x: Date.parse(k.first_seen), label: "KEV " + k.cve, color: "#b07cff", row: 3 });
  draw("timeline", {
    type: "line",
    data: {
      datasets: [
        { label: "exploit-confidence", data: t.hits.map((p) => ({ x: Date.parse(p.t), y: p.exploit })), borderColor: "#ff5d5d", tension: 0.2 },
        { label: "all hits", data: t.hits.map((p) => ({ x: Date.parse(p.t), y: p.total })), borderColor: "#8a94a0", tension: 0.2 },
      ],
    },
    options: {
      animation: false,
      parsing: false,
      scales: { x: { type: "linear", ticks: { callback: (v) => new Date(v).toLocaleString() , maxTicksLimit: 6 } }, y: { beginAtZero: true } },
      plugins: { markers },
    },
  });
}

async function sources() {
  const s = await get("/api/sources?window=" + encodeURIComponent($("window").value));
  const rows = s.rows.map((r) => {
    const tr = document.createElement("tr");
    const cells = [[r.country || "?"], [(r.asn ?? "?") + (r.asn_name ? " " + r.asn_name : "")], [r.exploit_hits, "r"], [r.hits, "r"]];
    for (const [v, cls] of cells) { const td = document.createElement("td"); td.textContent = v; if (cls) td.className = cls; tr.append(td); }
    return tr;
  });
  $("sources").replaceChildren(...rows);
}

async function iocs() {
  const d = await get("/api/iocs?window=" + encodeURIComponent($("window").value));
  const body = $("iocs");
  if (!d.iocs.length) {
    const tr = document.createElement("tr"), td = document.createElement("td");
    td.colSpan = 7; td.className = "l"; td.textContent = "no exploit-confidence source IPs in window";
    tr.append(td); body.replaceChildren(tr);
    return;
  }
  const rows = d.iocs.map((r) => {
    const tr = document.createElement("tr");
    const cells = [
      [r.ip || "?"],
      [r.country || "?"],
      [(r.asn ?? "?") + (r.asn_name ? " " + r.asn_name : "")],
      [(r.signatures || []).join(", ")],
      [r.exploit_hits, "r"],
      [r.total_hits, "r"],
      [r.last_seen ? new Date(r.last_seen).toLocaleString() : "?"],
    ];
    for (const [v, cls] of cells) { const td = document.createElement("td"); td.textContent = v; if (cls) td.className = cls; tr.append(td); }
    return tr;
  });
  body.replaceChildren(...rows);
}

async function adoption() {
  const a = await get("/api/adoption");
  draw("adoption", {
    type: "line",
    data: {
      labels: a.series.map((p) => new Date(p.t).toLocaleDateString()),
      datasets: [
        { label: "fixed", data: a.series.map((p) => p.fixed), borderColor: "#4cc38a" },
        { label: "vulnerable", data: a.series.map((p) => p.vulnerable), borderColor: "#ff5d5d" },
      ],
    },
    options: { animation: false },
  });
}

async function claims() {
  const c = await get("/api/claims");
  $("claims").replaceChildren(...c.claims.map((x) => {
    const li = document.createElement("li");
    li.append(new Date(x.ts).toLocaleDateString() + " " + x.org + ": " + x.claim + " ");
    if (/^https?:\/\//.test(x.url || "")) {
      const l = document.createElement("a"); l.href = x.url; l.textContent = "[source]"; l.rel = "noopener noreferrer"; li.append(l);
    }
    return li;
  }));
}

async function status() {
  const s = await get("/api/status");
  const stale = s.collectors.filter((c) => c.stale).map((c) => c.source);
  $("status").textContent = stale.length ? "stale feeds: " + stale.join(", ") : "feeds ok";
  $("status").className = stale.length ? "stale" : "ok";
}

async function refresh() {
  await Promise.allSettled([headline(), timeline(), sources(), iocs(), adoption(), claims(), status()]);
}
$("window").addEventListener("change", () => { timeline(); sources(); iocs(); });
refresh();
setInterval(refresh, 60000);
