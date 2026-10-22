"use strict";
const $ = (id) => document.getElementById(id);
const charts = {};
let WINDOW = "24h";
let PATCH_MS = Date.parse("2026-10-21T14:00:00Z");

// ---- theme toggle (per-viewer convenience; falls back silently) ----
(function initTheme() {
  try {
    const saved = localStorage.getItem("php2mon-theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
  } catch (e) { /* storage blocked */ }
})();
$("theme").addEventListener("click", () => {
  const cur = document.documentElement.getAttribute("data-theme");
  const dark = matchMedia("(prefers-color-scheme: dark)").matches;
  const next = cur ? (cur === "dark" ? "light" : "dark") : (dark ? "light" : "dark");
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("php2mon-theme", next); } catch (e) { /* ignore */ }
  restyleCharts();
});
const cssvar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

// ---- Chart.js phosphor defaults ----
Chart.defaults.font.family = '"JetBrains Mono", ui-monospace, monospace';
Chart.defaults.font.size = 10;
Chart.defaults.animation = false;

const markerPlugin = {
  id: "markers",
  afterDatasetsDraw(chart) {
    const { ctx, chartArea, scales } = chart;
    for (const m of chart.options.plugins.markers || []) {
      const x = scales.x.getPixelForValue(m.x);
      if (x < chartArea.left || x > chartArea.right) continue;
      ctx.save();
      ctx.strokeStyle = m.color;
      ctx.setLineDash([3, 3]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x, chartArea.top);
      ctx.lineTo(x, chartArea.bottom);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = m.color;
      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.fillText(m.label, x + 4, chartArea.top + 11 + (m.row || 0) * 13);
      ctx.restore();
    }
  },
};
Chart.register(markerPlugin);

function draw(id, config) {
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($(id), config);
}
function restyleCharts() { timeline(); adoption(); }

async function get(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + " " + r.status);
  return r.json();
}
const fmt = (n) => (n == null ? "—" : Number(n).toLocaleString("en-US"));

// ---- patch-elapsed counter (ticks every second) ----
function tick() {
  const d = Date.now() - PATCH_MS;
  const el = $("elapsed");
  if (d < 0) { el.textContent = "pending"; return; }
  const s = Math.floor(d / 1000);
  const hh = String(Math.floor(s / 3600)).padStart(2, "0");
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  el.textContent = `${hh}:${mm}:${ss}`;
}

async function headline() {
  const h = await get("/api/headline");
  if (h.patch_release) PATCH_MS = Date.parse(h.patch_release);
  const rs = $("readouts").children;

  // hero: exploit-confidence hits since patch — calm when 0, alert when >0
  const ex = h.exploit_hits_since_patch ?? 0;
  const hero = rs[0];
  hero.classList.toggle("state-alert", ex > 0);
  hero.classList.toggle("state-ok", ex === 0);
  const vEx = hero.querySelector(".v");
  vEx.classList.remove("skeleton");
  vEx.textContent = fmt(ex);
  const tag = $("exploit-tag");
  tag.textContent = ex > 0 ? "ACTIVE" : "ALL CLEAR";
  tag.className = "tag " + (ex > 0 ? "alert" : "ok");
  $("exploit-sub").textContent = ex > 0
    ? (fmt(h.current_hour_exploit_hits ?? 0) + " this hour · since patch release")
    : "none since patch release · watch active";

  setReadout(rs[1], fmt(h.total_hits_24h));
  setReadout(rs[2], fmt(h.unique_ips_24h));
  setReadout(rs[3], h.l7_attacks_latest == null ? "n/a" : fmt(h.l7_attacks_latest));
  if (h.l7_attacks_latest == null) rs[3].querySelector(".v").classList.add("num-zero");
}
function setReadout(node, text) {
  const v = node.querySelector(".v");
  v.classList.remove("skeleton");
  v.textContent = text;
}

async function timeline() {
  const t = await get("/api/timeline?window=" + encodeURIComponent(WINDOW));
  const a = t.annotations;
  const red = cssvar("--red"), amber = cssvar("--amber"), blue = cssvar("--blue"),
        mut = cssvar("--mut"), rule = cssvar("--rule"), green = cssvar("--green");
  const narrow = window.innerWidth < 560;
  const markers = [{ x: Date.parse(a.patch_release), label: narrow ? "patch" : "patch release", color: amber, row: 0 }];
  if (a.embargo) markers.push({ x: Date.parse(a.embargo), label: "embargo", color: amber, row: 1 });
  if (a.cf_rules) markers.push({ x: Date.parse(a.cf_rules), label: narrow ? "CF" : "CF rules", color: blue, row: 2 });
  for (const k of a.kev) markers.push({ x: Date.parse(k.first_seen), label: narrow ? "KEV" : "KEV " + k.cve, color: red, row: narrow ? 1 : 3 });

  draw("timeline", {
    type: "line",
    data: {
      datasets: [
        { label: "exploit-confidence", data: t.hits.map((p) => ({ x: Date.parse(p.t), y: p.exploit })),
          borderColor: red, backgroundColor: red, pointRadius: 0, borderWidth: 2, tension: .25, fill: false },
        { label: "all hits", data: t.hits.map((p) => ({ x: Date.parse(p.t), y: p.total })),
          borderColor: mut, pointRadius: 0, borderWidth: 1, tension: .25, borderDash: [2, 2] },
      ],
    },
    options: {
      parsing: false,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      scales: {
        x: { type: "linear", grid: { color: rule, drawTicks: false },
             ticks: { color: mut, maxTicksLimit: narrow ? 4 : 6, maxRotation: 0, autoSkipPadding: 12,
                      callback: (v) => new Date(v).toLocaleString([], narrow ? { month: "short", day: "numeric" } : { month: "short", day: "numeric", hour: "2-digit" }) } },
        y: { beginAtZero: true, grid: { color: rule, drawTicks: false }, ticks: { color: mut, precision: 0, maxTicksLimit: 5 } },
      },
      plugins: {
        markers,
        legend: { labels: { color: mut, boxWidth: 10, boxHeight: 2, font: { size: 10 } } },
        tooltip: { backgroundColor: cssvar("--rail"), borderColor: rule, borderWidth: 1,
                   titleColor: cssvar("--ink"), bodyColor: cssvar("--ink"), displayColors: true, padding: 8 },
      },
    },
  });
}

async function iocs() {
  const d = await get("/api/iocs?window=" + encodeURIComponent(WINDOW));
  $("ioc-meta").textContent = d.iocs.length
    ? d.iocs.length + " source" + (d.iocs.length === 1 ? "" : "s") + " · " + WINDOW
    : WINDOW;
  const body = $("ioc-body");
  if (!d.iocs.length) {
    body.innerHTML = "";
    const e = document.createElement("div");
    e.className = "empty allclear";
    const big = document.createElement("div"); big.className = "big"; big.textContent = "NO EXPLOIT-CONFIDENCE SOURCES";
    const sm = document.createElement("div"); sm.className = "small";
    sm.textContent = "Watch active. No source IP has tripped an exploit signature in this window.";
    e.append(big, sm); body.replaceChildren(e);
    return;
  }
  const max = Math.max(...d.iocs.map((r) => r.exploit_hits || 0), 1);
  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>Source IP</th><th class='c-geo'>Geo</th><th class='c-asn'>ASN</th><th class='c-sig'>Signatures</th>" +
    "<th class='r c-exploit'>Exploit</th><th class='r c-total'>Total</th><th class='c-last'>Last seen</th></tr></thead>";
  const tb = document.createElement("tbody");
  for (const r of d.iocs) {
    const tr = document.createElement("tr");
    const sigs = (r.signatures || []).map((s) => `<span class="sig">${esc(s)}</span>`).join("");
    const last = r.last_seen ? new Date(r.last_seen).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
    const asn = (r.asn ?? "—") + (r.asn_name ? " " + r.asn_name : "");
    const ip = esc(r.ip || "—");
    const pct = Math.round(((r.exploit_hits || 0) / max) * 100);
    tr.innerHTML =
      `<td class="ip" title="${ip}">${ip}</td>` +
      `<td class="muted c-geo">${esc(r.country || "—")}</td>` +
      `<td class="muted asn c-asn" title="${esc(asn)}">${esc(asn)}</td>` +
      `<td class="c-sig">${sigs}</td>` +
      `<td class="r num-alert c-exploit">${fmt(r.exploit_hits)}<div class="bar" style="width:${pct}%"></div></td>` +
      `<td class="r muted c-total">${fmt(r.total_hits)}</td>` +
      `<td class="muted c-last">${last}</td>`;
    tb.append(tr);
  }
  table.append(tb);
  body.replaceChildren(table);
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function sources() {
  const s = await get("/api/sources?window=" + encodeURIComponent(WINDOW));
  const body = $("sources");
  if (!s.rows.length) { body.innerHTML = "<tr><td colspan='4' class='muted' style='padding:16px'>no traffic in window</td></tr>"; return; }
  body.replaceChildren(...s.rows.map((r) => {
    const tr = document.createElement("tr");
    const ex = r.exploit_hits || 0;
    const asn2 = esc((r.asn ?? "?") + (r.asn_name ? " " + r.asn_name : ""));
    tr.innerHTML =
      `<td>${esc(r.country || "?")}</td>` +
      `<td class="muted asn" title="${asn2}">${asn2}</td>` +
      `<td class="r ${ex ? "num-alert" : "num-zero"}">${fmt(ex)}</td>` +
      `<td class="r muted">${fmt(r.hits)}</td>`;
    return tr;
  }));
}

async function adoption() {
  const a = await get("/api/adoption");
  const empty = $("adoption-empty");
  if (!a.series.length) {
    if (charts.adoption) { charts.adoption.destroy(); delete charts.adoption; }
    $("adoption").style.display = "none";
    empty.innerHTML = '<div class="empty"><div class="big skeleton">NO DATA</div>' +
      '<div class="small">Shodan collector disabled — add an API key to populate patch adoption.</div></div>';
    return;
  }
  $("adoption").style.display = "";
  empty.innerHTML = "";
  const green = cssvar("--green"), danger = cssvar("--danger-soft"), mut = cssvar("--mut"), rule = cssvar("--rule");
  draw("adoption", {
    type: "line",
    data: {
      labels: a.series.map((p) => new Date(p.t).toLocaleDateString([], { month: "short", day: "numeric" })),
      datasets: [
        { label: "fixed", data: a.series.map((p) => p.fixed), borderColor: green, backgroundColor: green, pointRadius: 0, borderWidth: 2, tension: .25 },
        { label: "vulnerable", data: a.series.map((p) => p.vulnerable), borderColor: danger, backgroundColor: danger, pointRadius: 0, borderWidth: 2, tension: .25 },
      ],
    },
    options: {
      scales: { x: { grid: { color: rule, drawTicks: false }, ticks: { color: mut } },
                y: { grid: { color: rule, drawTicks: false }, ticks: { color: mut } } },
      plugins: { legend: { labels: { color: mut, boxWidth: 10, boxHeight: 2 } } },
    },
  });
}

async function claims() {
  const c = await get("/api/claims");
  const ul = $("claims");
  if (!c.claims.length) { ul.innerHTML = '<li class="muted">no attributed reports logged yet</li>'; return; }
  ul.replaceChildren(...c.claims.map((x) => {
    const li = document.createElement("li");
    const when = document.createElement("span"); when.className = "when";
    when.textContent = new Date(x.ts).toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
    const txt = document.createElement("span");
    const org = document.createElement("span"); org.className = "org"; org.textContent = x.org;
    txt.append(org, document.createTextNode(" " + x.claim + " "));
    if (/^https?:\/\//.test(x.url || "")) {
      const l = document.createElement("a"); l.href = x.url; l.textContent = "[source]"; l.rel = "noopener noreferrer"; txt.append(l);
    }
    li.append(when, txt);
    return li;
  }));
}

async function status() {
  const s = await get("/api/status");
  const feeds = $("feeds");
  const okN = s.collectors.filter((c) => !c.stale && !c.last_error).length;
  feeds.replaceChildren();
  const lbl = document.createElement("span");
  lbl.textContent = "FEEDS " + okN + "/" + s.collectors.length;
  lbl.style.letterSpacing = ".1em";
  feeds.append(lbl);
  for (const c of s.collectors) {
    const d = document.createElement("span");
    const cls = c.last_error ? "err" : c.stale ? "stale" : "ok";
    d.className = "dot " + cls;
    d.title = c.source + ": " + (c.last_error ? "error — " + c.last_error : c.stale ? "stale" : "ok") +
      (c.last_ok ? " (last ok " + new Date(c.last_ok).toLocaleString() + ")" : "");
    feeds.append(d);
  }
  // sensor pulse: green when a feed path is healthy, amber if all feeds down
  $("pulse").style.background = okN > 0 ? cssvar("--green") : cssvar("--amber");
}

async function refresh() {
  await Promise.allSettled([headline(), timeline(), iocs(), sources(), adoption(), claims(), status()]);
  // ping the live dot once per successful refresh cycle (event-driven liveness)
  const d = $("pulse");
  d.classList.remove("ping"); void d.offsetWidth; d.classList.add("ping");
}
for (const b of $("window").querySelectorAll("button")) {
  b.addEventListener("click", () => {
    WINDOW = b.dataset.w;
    for (const x of $("window").querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
    timeline(); iocs(); sources();
  });
}
tick(); setInterval(tick, 1000);
refresh(); setInterval(refresh, 60000);
