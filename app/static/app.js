"use strict";
// DEEPSIGHT web UI (vanilla JS, no build step). All dynamic data is escaped via esc(); no inline handlers (CSP-safe).
// Sections: 1 utils · 2 icons/charts · 3 modal/toast · 4 shell+assistant · 5 pages · 6 integrations · 7 events+boot
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const S = { token: null, user: null, ai: false, aiBusy: false, hist: [], tab: {}, ctx: {}, rid: 0, route: "", sort: {}, q: {}, int: { sel: null, fb: {} }, gsel: null };
try { S.token = sessionStorage.getItem("t"); S.user = JSON.parse(sessionStorage.getItem("u") || "null"); } catch (e) {}
const NAV = [
  ["Monitor", ["overview", "queue", "assets", "findings", "infrastructure"]],
  ["Analyze", ["intelligence", "investigations", "reports"]],
  ["Platform", ["integrations", "search", "admin"]],
];
const NAMES = { admin: "Administration", queue: "Work queue", search: "Global search" };
const WRITE = () => ["administrator", "analyst"].includes(S.user?.role);
const ADMIN = () => S.user?.role === "administrator";

// ================================================================ 1. utils
async function api(path, opt = {}) {
  const token = S.token;
  const o = { method: opt.method || "GET", headers: { Authorization: "Bearer " + token } };
  if (opt.body !== undefined) { o.body = JSON.stringify(opt.body); o.headers["Content-Type"] = "application/json"; }
  let r;
  try { r = await fetch("/api" + path, o); } catch (e) { throw new Error("Cannot reach the DEEPSIGHT server. Check your connection and try again."); }
  if (r.status === 401 && path !== "/auth/login") { if (token === S.token) logout(); throw new Error("Your session expired. Please sign in again."); }
  if (!r.ok) {
    let d = ""; try { d = (await r.json()).detail; } catch (e) {}
    if (Array.isArray(d)) d = d.map(x => (x && x.msg) ? `${(x.loc || []).slice(1).join(".") || "input"}: ${x.msg}` : JSON.stringify(x)).join("; ");
    throw new Error(typeof d === "string" && d ? d : (d ? JSON.stringify(d) : r.statusText));
  }
  return opt.raw ? r : r.json();
}
const num = (n, d = 2) => n == null ? "–" : (+n).toFixed(d);
const ts = t => t ? esc(String(t).replace("T", " ").replace("Z", "")) : "";
const parseT = t => { const d = new Date(/Z$|[+-]\d\d:?\d\d$/.test(t) ? t : t + "Z"); return isNaN(d) ? null : d; };
function ago(t) {
  const d = t && parseT(t); if (!d) return "";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 0) return "in the future"; if (s < 45) return "just now"; if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago"; if (s < 86400 * 14) return Math.round(s / 86400) + "d ago";
  return String(t).slice(0, 10);
}
const when = t => t ? `<span class="nowrap" title="${ts(t)} UTC">${esc(ago(t))}</span>` : '<span class="mut">–</span>';
const dur = (a, b) => { const x = a && parseT(a), y = b && parseT(b); if (!x || !y) return "–"; const s = Math.max(0, Math.round((y - x) / 1000)); return s < 60 ? s + "s" : s < 3600 ? Math.floor(s / 60) + "m " + (s % 60) + "s" : Math.floor(s / 3600) + "h " + Math.floor(s % 3600 / 60) + "m"; };
const human = s => String(s ?? "").replace(/_/g, " ");
const badge = (t, cls = "") => `<span class="badge ${esc(cls)}">${esc(t)}</span>`;
const lv = l => `<span class="badge ${esc(l)}">${esc(l || "n/a")}</span>`;
const basis = b => `<span class="badge ${esc(b)}">${esc(b)}</span>`;
const link = (h, t) => `<a href="#/${esc(h)}">${esc(t)}</a>`;
const bytes = n => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
const sevCls = s => ["critical", "high", "medium", "low"].includes(s) ? s : "unknown";
const cvssBadge = (v, sev) => v == null ? '<span class="mut">–</span>' : `<span class="badge ${sevCls(sev)}" title="Published CVSS severity: ${esc(sev || "unknown")}">${num(v, 1)}</span>`;
const scoreCell = (score, level) => `<div class="score"><b>${num(score, 0)}</b><div class="meter ${esc(level)}"><i style="width:${Math.max(0, Math.min(100, +score || 0))}%"></i></div>${lv(level)}</div>`;
const runBadge = s => ({ ok: badge("Success", "ok"), partial: badge("Partial", "partial"), error: badge("Failed", "error"), running: `<span class="badge running"><span class="dot running"></span>Running</span>` }[s] || badge(s || "unknown", "neutral"));
const anomBadge = s => badge(human(s), { new: "warn", true_positive: "error", false_positive: "neutral", reviewed: "info" }[s] || "neutral");
const kevBadge = k => k ? ' <span class="badge kev">KEV</span>' : "";
const initials = n => esc(String(n || "?").slice(0, 2));
const fmtJson = o => JSON.stringify(o, null, 2).replace(/\[\s+([^\[\]{}]*?)\s+\]/g, (m, i) => "[" + i.replace(/\s*\n\s*/g, " ") + "]");
async function copyText(t) { try { await navigator.clipboard.writeText(t); toast("Copied to clipboard", "ok"); } catch (e) { toast("Copy failed — select the text manually", "warn"); } }
function download(blob, name) { const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); }
async function busy(btn, fn) {
  if (!btn) return fn(); if (btn.disabled) return;
  const html = btn.innerHTML; btn.disabled = true; btn.innerHTML = `<span class="spin"></span>${btn.textContent.trim() ? "Working…" : ""}`;
  try { return await fn(); } finally { if (btn.isConnected) { btn.disabled = false; btn.innerHTML = html; } }
}

// ================================================================ 2. icons + charts
const ICONS = {
  overview: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
  assets: '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
  findings: '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M12 8v4M12 16h.01"/>',
  infrastructure: '<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-2a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v2"/>',
  intelligence: '<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
  investigations: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3M8.5 11l2 2 3.5-4"/>',
  reports: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
  integrations: '<path d="M9 2v5M15 2v5M6 7h12v4a6 6 0 0 1-12 0V7zM12 17v5"/>',
  admin: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  assistant: '<path d="M21 15a2 2 0 0 1-2 2H8l-5 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><path d="M8 9h8M8 13h5"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  refresh: '<path d="M21 12a9 9 0 0 1-15.5 6.2L3 16M3 12a9 9 0 0 1 15.5-6.2L21 8M21 3v5h-5M3 21v-5h5"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>', check: '<path d="M20 6L9 17l-5-5"/>', plus: '<path d="M12 5v14M5 12h14"/>', menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
  alert: '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  xcircle: '<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>', ok: '<circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-6"/>',
  upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  play: '<path d="M6 4l14 8-14 8z"/>', flask: '<path d="M9 3h6M10 3v6L4.5 19a2 2 0 0 0 1.8 3h11.4a2 2 0 0 0 1.8-3L14 9V3"/><path d="M7 15h10"/>',
  history: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>', copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeoff: '<path d="M3 3l18 18M10.6 5.1A9.8 9.8 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4M6.6 6.6A17 17 0 0 0 2 12s3.6 7 10 7a9.7 9.7 0 0 0 4.3-1M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
  shieldok: '<path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>', external: '<path d="M15 3h6v6M10 14L21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  server: '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/>',
  workstation: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
  network_device: '<rect x="2" y="14" width="20" height="7" rx="2"/><path d="M6 18h.01M10 18h.01M12 14V8M8.5 9.5a5 5 0 0 1 7 0"/>',
  cloud_resource: '<path d="M7 18a4 4 0 0 1-.6-7.9A6 6 0 0 1 18 9.5 4.5 4.5 0 0 1 17.5 18z"/>',
  virtual_machine: '<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3 8l9 5 9-5M12 13v8"/>',
  container: '<path d="M12 2l10 5-10 5L2 7z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/>',
  iot_device: '<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4M7.8 16.2a6 6 0 0 1 0-8.4M19 5a10 10 0 0 1 0 14M5 19A10 10 0 0 1 5 5"/>',
  unknown: '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01"/>',
  chev: '<path d="M9 6l6 6-6 6"/>', merge: '<circle cx="6" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 8v2a4 4 0 0 0 4 4h6M6 16v-2"/>',
  plus2: '<circle cx="12" cy="12" r="10"/><path d="M12 8v8M8 12h8"/>', zoomin: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3M11 8v6M8 11h6"/>', zoomout: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3M8 11h6"/>', fit: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
};
const ic = (n, c = "") => `<svg class="ic ${c}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ICONS.unknown}</svg>`;
const typeIc = t => ic(ICONS[t] ? t : "unknown");
const brandMark = () => `<svg viewBox="0 0 32 32" aria-hidden="true"><rect x=".5" y=".5" width="31" height="31" rx="8" fill="#0e131b" stroke="#2b3749"/><path d="M4 16Q16 5.5 28 16 16 26.5 4 16Z" fill="none" stroke="#38bdd0" stroke-width="1.8" stroke-linejoin="round"/><circle cx="16" cy="16" r="5.4" fill="none" stroke="#38bdd0" stroke-opacity=".5" stroke-width="1.2"/><circle cx="16" cy="16" r="2.6" fill="#38bdd0"/><path d="M16 2.5v3M16 26.5v3" stroke="#38bdd0" stroke-opacity=".55" stroke-width="1.4" stroke-linecap="round"/></svg>`;

const LV_COL = { critical: "#f0534f", high: "#f2893d", medium: "#e6b73a", low: "#4cc38a", verify: "#8e92f0", unknown: "#5d6a7d" };
function empty(icon, title, hint = "") { return `<div class="empty">${ic(icon)}<b>${esc(title)}</b>${hint ? `<div>${esc(hint)}</div>` : ""}</div>`; }
function table(cols, rows, rowLink, opt = {}) {
  const th = cols.map((c, i) => { const o = typeof c === "string" ? { h: c } : c; const s = opt.sort && o.key !== undefined ? S.sort[opt.sort.id] : null;
    return `<th class="${esc(o.cls || "")} ${s && s.i === i ? "sorted" : ""}" ${o.key !== undefined && opt.sort ? `data-sort="${i}" data-tb="${esc(opt.sort.id)}" tabindex="0" aria-sort="${s && s.i === i ? (s.dir < 0 ? "descending" : "ascending") : "none"}"` : ""}>${esc(o.h)}${o.key !== undefined && opt.sort ? `<span class="ar">${s && s.i === i && s.dir < 0 ? "↓" : "↑"}</span>` : ""}</th>`; }).join("");
  const body = rows.map(r => `<tr class="${rowLink ? "row" : ""}" ${rowLink ? `data-go="${esc(rowLink(r))}" tabindex="0"` : ""}>${r.cells.map(c => `<td>${c}</td>`).join("")}</tr>${r.after || ""}`).join("");
  return `<div class="tw"><table class="t"><thead><tr>${th}</tr></thead><tbody>${body || `<tr><td colspan="${cols.length}">${opt.empty || empty("search", "No records")}</td></tr>`}</tbody></table></div>`;
}
// client-side sortable/filterable table (data comes from the existing API call; sorting never changes the request)
const TBL = {};
function stable(id, cols, items, rowFn, rowLink, def, opt = {}) {
  TBL[id] = { cols, items, rowFn, rowLink, opt }; if (def && !S.sort[id]) S.sort[id] = def;
  return `<div id="tb-${id}">${stableInner(id)}</div>`;
}
function stableInner(id) {
  const T = TBL[id], s = S.sort[id], q = (S.q[id] || "").toLowerCase(); let items = T.items.slice();
  if (q && T.opt.match) items = items.filter(x => T.opt.match(x).toLowerCase().includes(q));
  if (s) { const c = T.cols[s.i], f = typeof c.key === "function" ? c.key : x => x[c.key];
    items.sort((a, b) => { let x = f(a), y = f(b); const nx = x == null || x === "", ny = y == null || y === ""; if (nx || ny) return nx === ny ? 0 : nx ? 1 : -1;
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * s.dir; }); }
  const shown = `<div class="pager">${items.length === T.items.length ? `${items.length} record${items.length === 1 ? "" : "s"}` : `${items.length} of ${T.items.length} records match`}${T.opt.note ? " · " + T.opt.note : ""}</div>`;
  return table(T.cols, items.map(T.rowFn), T.rowLink, { sort: { id }, empty: T.opt.empty }) + (T.items.length ? shown : "");
}

function bars(o, colors) {
  const e = Object.entries(o || {}), m = Math.max(1, ...e.map(x => x[1]));
  return e.length ? e.map(([k, v]) => `<div class="hbar"><span class="k" title="${esc(human(k))}">${esc(human(k))}</span><div class="meter ${colors ? esc(k) : ""}"><i style="width:${100 * v / m}%"></i></div><span class="v">${v}</span></div>`).join("") : empty("search", "No data");
}
function donut(segs, label) {
  const R = 46, C = 2 * Math.PI * R, tot = segs.reduce((a, s) => a + s.value, 0), live = segs.filter(s => s.value > 0).length; let off = 0;
  const arcs = tot ? segs.filter(s => s.value > 0).map(s => { const len = Math.max(0, C * s.value / tot - (live > 1 ? 2 : 0)); const el = `<circle cx="70" cy="70" r="${R}" fill="none" stroke="${s.color}" stroke-width="16" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 70 70)"><title>${esc(s.label)}: ${s.value}</title></circle>`; off += C * s.value / tot; return el; }).join("")
    : `<circle cx="70" cy="70" r="${R}" fill="none" stroke="#1c2533" stroke-width="16"/>`;
  return `<svg viewBox="0 0 140 140" role="img" aria-label="${esc(label)}">${arcs}<text x="70" y="68" text-anchor="middle" style="font-size:26px;font-weight:600;fill:#e3e8ef">${tot}</text><text x="70" y="86" text-anchor="middle" class="ax">${esc(label)}</text></svg>`;
}
const legend = segs => `<div class="legend">${segs.map(s => `<div><i class="sw" style="background:${s.color}"></i>${esc(s.label)}<b>${s.value}</b></div>`).join("")}</div>`;
const stackbar = segs => { const t = segs.reduce((a, s) => a + s.value, 0) || 1; return `<div class="stackbar">${segs.filter(s => s.value > 0).map(s => `<i style="width:${100 * s.value / t}%;background:${s.color}" title="${esc(s.label)}: ${s.value}"></i>`).join("")}</div>`; };
function lineChart(days, vals, color, name) {
  const W = 520, H = 150, L = 30, R = 8, T = 10, B = 22, mx = Math.max(1, ...vals), n = vals.length;
  const X = i => L + (n < 2 ? 0 : i * (W - L - R) / (n - 1)), Y = v => T + (H - T - B) * (1 - v / mx);
  const pts = vals.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(" ");
  const ticks = [0, Math.round(mx / 2), mx].filter((v, i, a) => a.indexOf(v) === i);
  const lab = i => `<text class="ax" x="${X(i)}" y="${H - 6}" text-anchor="${i === 0 ? "start" : i === n - 1 ? "end" : "middle"}">${esc((days[i] || "").slice(5))}</text>`;
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="${esc(name)}, last ${n} days">${ticks.map(v => `<line class="gl" x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}"/><text class="ax" x="${L - 6}" y="${Y(v) + 3}" text-anchor="end">${v}</text>`).join("")}${n ? `<polygon points="${X(0)},${Y(0)} ${pts} ${X(n - 1)},${Y(0)}" fill="${color}" fill-opacity=".1"/><polyline fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" points="${pts}"/>${vals.map((v, i) => `<circle cx="${X(i)}" cy="${Y(v)}" r="2.6" fill="${color}"><title>${esc(days[i])}: ${v}</title></circle>`).join("")}${lab(0)}${n > 2 ? lab(Math.floor((n - 1) / 2)) : ""}${n > 1 ? lab(n - 1) : ""}` : ""}</svg>`;
}
function metricsGrid(o, skip = ["caveat"], pre = "") {
  const out = [];
  for (const [k, v] of Object.entries(o || {})) { if (skip.includes(k)) continue;
    if (v && typeof v === "object" && !Array.isArray(v)) out.push(metricsGrid(v, skip, pre + k + "."));
    else out.push(`<div><div class="mk">${esc(human(pre + k))}</div><div class="mv">${typeof v === "number" ? (Number.isInteger(v) ? v : +v.toFixed(4)) : Array.isArray(v) ? esc(JSON.stringify(v)) : esc(v ?? "–")}</div></div>`); }
  return pre ? out.join("") : `<div class="metrics">${out.join("")}</div>`;
}
const jsonView = (o, id = "") => `<div class="jwrap"><button class="btn sm ghost" data-copy="${esc(id)}" type="button">${ic("copy", "sm")}Copy</button><pre class="json" ${id ? `id="${esc(id)}"` : ""}>${esc(fmtJson(o))}</pre></div>`;
const callout = (icon, html, cls = "") => `<div class="callout ${cls}">${ic(icon)}<div>${html}</div></div>`;
const panel = (title, body, hint = "", cls = "") => `<section class="panel ${cls}">${title ? `<div class="ph2"><h3>${esc(title)}</h3>${hint ? `<span class="hint">${hint}</span>` : ""}</div>` : ""}${body}</section>`;
const pb = h => `<div class="pb">${h}</div>`;
const ph = (title, sub = "", acts = "", crumb = "") => `<div class="ph"><div>${crumb ? `<div class="crumb">${crumb}</div>` : ""}<h1>${title}</h1>${sub ? `<div class="sub">${sub}</div>` : ""}</div>${acts ? `<div class="acts">${acts}</div>` : ""}</div>`;

// ================================================================ 3. modal / toast / confirm
function toast(m, kind) {
  kind = kind === true ? "err" : (kind || "info"); const t = document.createElement("div"); t.className = "toast " + (kind === "ok" ? "ok" : kind); t.setAttribute("role", kind === "err" ? "alert" : "status");
  t.innerHTML = `${ic({ ok: "ok", err: "xcircle", warn: "alert", info: "info" }[kind] || "info")}<div class="tm">${esc(m)}</div><button aria-label="Dismiss">${ic("x", "sm")}</button>`;
  t.querySelector("button").onclick = () => t.remove(); $("#toasts").append(t); setTimeout(() => t.remove(), kind === "err" ? 8000 : 4500);
}
const modalClosers = new Set();
function openModal({ title, body, footer = "", size = "", persist = false, onClose }) {
  const back = document.createElement("div"); back.className = "mback"; const prev = document.activeElement;
  back.innerHTML = `<div class="modal ${size}" role="dialog" aria-modal="true" aria-label="${esc(title)}"><header><h3>${esc(title)}</h3><button class="iconbtn" data-mclose aria-label="Close">${ic("x")}</button></header><div class="mb">${body}</div>${footer ? `<footer>${footer}</footer>` : ""}</div>`;
  const key = e => {
    if (back !== $("#modal-root").lastElementChild) return;
    if (e.key === "Escape") { e.preventDefault(); close(); }
    if (e.key === "Tab") {
      const focusable = $$("button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex='0']", back).filter(el => el.getClientRects().length);
      const first = focusable[0], last = focusable.at(-1);
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
    }
  };
  let closed = false;
  const close = v => { if (closed) return; closed = true; modalClosers.delete(close); document.removeEventListener("keydown", key); back.remove(); if (!modalClosers.size) $("#app").inert = false; if (prev && prev.isConnected) prev.focus(); onClose && onClose(v); };
  back.addEventListener("mousedown", e => { if (e.target === back && !persist) close(); });
  $("[data-mclose]", back).onclick = () => close(); document.addEventListener("keydown", key);
  modalClosers.add(close); $("#app").inert = true;
  $("#modal-root").append(back); const f = $("input:not([type=hidden]):not(:disabled),select:not(:disabled),textarea:not(:disabled),.btn.pri", back) || $("[data-mclose]", back); f.focus();
  return { el: back, q: s => $(s, back), close };
}
function confirmDialog({ title, message, confirm = "Confirm", danger = false }) {
  return new Promise(res => { let done = false;
    const m = openModal({ title, size: "sm", body: `<p style="margin:0;color:var(--tx2)">${esc(message)}</p>`, onClose: () => { if (!done) res(false); },
      footer: `<button class="btn" data-c="0">Cancel</button><button class="btn ${danger ? "dng solid" : "pri"}" data-c="1">${esc(confirm)}</button>` });
    $$("[data-c]", m.el).forEach(b => b.onclick = () => { done = true; res(b.dataset.c === "1"); m.close(); });
  });
}

// ================================================================ 4. shell, login, assistant, router
function logout() {
  for (const close of [...modalClosers]) close();
  Object.assign(S, { token: null, user: null, hist: [], ai: false, aiBusy: false, tab: {}, ctx: {}, route: "", sort: {}, q: {}, int: { sel: null, fb: {} }, gsel: null });
  for (const key of Object.keys(TBL)) delete TBL[key];
  try { sessionStorage.removeItem("t"); sessionStorage.removeItem("u"); } catch (e) {}
  render();
}
function loginView() {
  $("#app").innerHTML = `<div class="login"><section class="hero"><div class="brand">${brandMark()}<div><b>DEEPSIGHT</b></div></div>
    <p class="product-description"><strong>MACHINE LEARNING-DRIVEN ATTACK SURFACE INTELLIGENCE AND VULNERABILITY MANAGEMENT PLATFORM</strong></p>
    <h1>See beyond<br><span style="color:var(--acc2)">the surface.</span></h1></section>
    <section class="form"><form id="lf" novalidate><h2>Sign in</h2><div class="mut">Use your DEEPSIGHT account to continue.</div>
    <div class="fld"><label for="lu">Username</label><input id="lu" name="u" autocomplete="username" required autofocus></div>
    <div class="fld"><label for="lp">Password</label><div class="pw"><input id="lp" name="p" type="password" autocomplete="current-password" required><button type="button" data-act="pw" aria-label="Show password">${ic("eye")}</button></div></div>
    <button class="btn pri" style="width:100%;margin-top:6px;padding:9px">Sign in</button><div id="le" class="ferr" role="alert" style="margin-top:12px"></div></form></section></div>`;
  document.title = "DEEPSIGHT · See beyond the surface.";
  $("#lf").onsubmit = async e => {
    e.preventDefault(); const f = new FormData(e.target), b = $("#lf .btn.pri"); $("#le").textContent = "";
    if (!f.get("u") || !f.get("p")) { $("#le").textContent = "Enter your username and password."; return; }
    b.disabled = true; b.innerHTML = '<span class="spin"></span>Signing in…';
    try { const r = await api("/auth/login", { method: "POST", body: { username: f.get("u"), password: f.get("p") } }); S.token = r.token; S.user = r.user; try { sessionStorage.setItem("t", r.token); sessionStorage.setItem("u", JSON.stringify(r.user)); } catch (x) {} render(); }
    catch (x) { $("#le").textContent = x.message; b.disabled = false; b.textContent = "Sign in"; }
  };
}
function buildShell() {
  const navHtml = NAV.map(([g, items]) => `<h6>${g}</h6>` + items.map(n => `<a href="#/${n}" data-nav="${n}">${ic(n)}<span>${esc(NAMES[n] || n[0].toUpperCase() + n.slice(1))}</span></a>`).join("")).join("");
  $("#app").innerHTML = `<div id="shell" class="${S.ai ? "ai" : ""}" data-ai="${S.ai}" data-user="${esc(S.user.username)}">
    <aside class="side" id="primary-sidebar"><div class="brand">${brandMark()}<div><b>DEEPSIGHT</b><small>See beyond the surface.</small></div><button class="iconbtn side-close" data-act="menu" aria-label="Close navigation">${ic("x")}</button></div>
      <nav class="nav" aria-label="Main">${navHtml}<h6>Assistant</h6><button class="navbtn ${S.ai ? "on" : ""}" data-act="ai">${ic("assistant")}<span>${S.ai ? "Hide" : "Ask"} assistant</span></button></nav>
      <div class="me"><div class="avatar">${initials(S.user.username)}</div><div class="who"><b>${esc(S.user.username)}</b><span>${esc(S.user.role)}</span></div><button class="iconbtn" data-act="logout" title="Sign out" aria-label="Sign out">${ic("logout")}</button></div></aside>
    <div class="scrim" data-act="menu"></div>
    <div class="mainwrap"><div class="mtop"><button class="iconbtn" data-act="menu" aria-label="Open navigation">${ic("menu", "lg")}</button><div class="brand">${brandMark()}<div><b>DEEPSIGHT</b></div></div><button class="iconbtn" style="margin-left:auto" data-act="ai" aria-label="Assistant">${ic("assistant", "lg")}</button></div><main id="main"></main></div>${S.ai ? aiPanel() : ""}</div>`;
  syncNavigation();
  if (S.ai) aiInit();
}
function syncNavigation() {
  const sh = $("#shell"); if (!sh) return;
  const open = sh.classList.contains("nav-open"), mobile = matchMedia("(max-width:960px)").matches;
  $(".side", sh).inert = mobile && !open;
  const toggle = $(".mtop [data-act=menu]", sh);
  toggle.setAttribute("aria-controls", "primary-sidebar"); toggle.setAttribute("aria-expanded", String(open));
}
function aiPanel() { return `<aside id="aip" aria-label="Investigation assistant"><header>${ic("assistant", "lg")}<div><b>DEEPSIGHT assistant</b><small>Grounded in platform evidence</small></div><button class="iconbtn" data-act="ai" aria-label="Close assistant">${ic("x")}</button></header><div id="msgs"></div><div id="sugs"></div><form id="af"><input id="aq" aria-label="Ask the investigation assistant" placeholder="Ask about assets, changes, risk…" maxlength="500" autocomplete="off"><button class="btn pri">Ask</button></form></aside>`; }
function aiInit() {
  const box = $("#msgs"); box.innerHTML = S.hist.length ? S.hist.map(m => `<div class="msg ${m.r}">${m.h}</div>`).join("") : `<div class="aiempty">Ask about an asset, a change or a risk. Answers cite platform evidence.</div>`; box.scrollTop = 1e9;
  $("#af").onsubmit = e => { e.preventDefault(); const q = $("#aq").value.trim(); if (q) ask(q); };
  $("#af button").disabled = S.aiBusy;
}
async function aiSuggest() {
  try { const s = await api("/assistant/suggestions" + (S.ctx.asset_id ? "?asset_id=" + S.ctx.asset_id : "")); const el = $("#sugs"); if (el) el.innerHTML = s.map(x => `<button class="sug" data-q="${esc(x)}">${esc(x)}</button>`).join(""); } catch (e) {}
}
const fmt = t => esc(t).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>");
async function ask(q) {
  if (S.aiBusy || !S.token) return;
  const token = S.token; S.aiBusy = true;
  if ($("#af button")) $("#af button").disabled = true;
  const add = (r, h) => { S.hist.push({ r, h }); const b = $("#msgs"); if (b) { $(".aiempty", b)?.remove(); b.insertAdjacentHTML("beforeend", `<div class="msg ${r}">${h}</div>`); b.scrollTop = 1e9; } };
  add("u", esc(q)); const inp = $("#aq"); if (inp) inp.value = "";
  const b = $("#msgs"); let th; if (b) { th = document.createElement("div"); th.className = "msg a think"; th.innerHTML = '<span class="spin"></span>Reviewing platform evidence…'; b.append(th); b.scrollTop = 1e9; }
  try {
    const r = await api("/assistant/query", { method: "POST", body: { question: q, context: S.ctx, history: S.hist.slice(-6).map(m => ({ role: m.r === "u" ? "user" : "assistant", content: m.h.replace(/<[^>]+>/g, "") })) } });
    if (token !== S.token) return;
    th?.remove();
    const refs = (r.references || []).slice(0, 12).map(x => { const m = { asset: "assets", finding: "findings", investigation: "investigations" }[x.type]; return m ? `<a href="#/${m}/${esc(x.id)}">${esc(x.label)}</a>` : esc(x.label); }).join(" · ");
    add("a", fmt(r.answer) + (refs ? `<div class="refs">References: ${refs}</div>` : "") + `<div class="mode">mode: ${esc(r.mode)}</div>`);
  } catch (e) { if (token === S.token) add("a", `<span class="ferr">${esc(e.message)}</span>`); }
  finally { th?.remove(); if (token === S.token) { S.aiBusy = false; if ($("#af button")) $("#af button").disabled = false; } }
}

const P = {};
const loadingHtml = () => `<div class="skel"><i class="h"></i><i></i><i class="b"></i></div>`;
const errState = e => `<div class="page">${callout("xcircle", `<b>Could not load this page.</b><div>${esc(e.message)}</div><div style="margin-top:8px"><button class="btn sm" data-act="retry">${ic("refresh", "sm")}Retry</button></div>`, "err")}</div>`;
const qs = () => new URLSearchParams((location.hash.split("?")[1] || ""));
const pageNumber = p => { const n = Number(p.get("page") || 1); return Number.isSafeInteger(n) && n > 0 ? n : 1; };
function pageLinks(route, params, total, page, size) {
  if (total <= size && page === 1) return "";
  const pages = Math.max(1, Math.ceil(total / size));
  const href = n => { const p = new URLSearchParams(params); p.set("page", n); return `#/${route}?${esc(p.toString())}`; };
  return `<nav class="pagination" aria-label="Results pages"><span>${total ? `${Math.min((page - 1) * size + 1, total)}–${Math.min(page * size, total)} of ${total}` : "0 results"} · Sorting applies to this page</span><div>${page > 1 ? `<a class="btn sm" href="${href(Math.min(page - 1, pages))}">Previous</a>` : ""}<span>Page ${page} of ${pages}</span>${page < pages ? `<a class="btn sm" href="${href(page + 1)}">Next</a>` : ""}</div></nav>`;
}
async function render() {
  if (S.restoring) return;
  if (!S.token || !S.user) { S.rid++; return loginView(); }
  const parts = location.hash.replace(/^#\//, "").split("?")[0].split("/"); const page = P[parts[0]] ? parts[0] : "overview";
  const route = location.hash || "#/overview", same = route === S.route; S.route = route; S.ctx = { page };
  const sh = $("#shell"); if (!sh || sh.dataset.ai !== String(S.ai) || sh.dataset.user !== S.user.username) buildShell();
  $("#shell").classList.remove("nav-open");
  syncNavigation();
  document.title = `${NAMES[page] || page[0].toUpperCase() + page.slice(1)} · DEEPSIGHT`;
  $$(".nav a[data-nav]").forEach(a => { a.classList.toggle("on", a.dataset.nav === page); if (a.dataset.nav === page) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  const m = $("#main"), rid = ++S.rid, keep = m.scrollTop;
  if (!same || !m.firstChild) m.innerHTML = `<div class="page">${loadingHtml()}</div>`;
  const pg = document.createElement("div"); pg.className = "page";
  try { await P[page](pg, parts[1]); } catch (e) { if (rid !== S.rid) return; m.replaceChildren(); m.insertAdjacentHTML("beforeend", errState(e)); return; }
  if (rid !== S.rid) return;               // a newer navigation superseded this render: discard
  m.replaceChildren(pg); m.scrollTop = same ? keep : 0;
  if (S.ai) aiSuggest();
  if (P[page].after) P[page].after(pg);
}

// ================================================================ 5. pages
const LEVELS = ["critical", "high", "medium", "low", "verify"];
P.overview = async m => {
  const d = await api("/overview"), k = d.metrics, ctx = d.findings_by_contextual_risk || {}, sev = d.findings_by_severity || {};
  const kpi = (l, v, h, o = {}) => `<a class="kpi ${o.cls || ""}" href="#/${h}"><div class="l"><span>${l}</span>${o.icon ? ic(o.icon, "sm") : ""}</div><div class="v">${v}</div>${o.sub ? `<div class="s">${o.sub}</div>` : ""}</a>`;
  const pct = k.assets_total ? Math.round(100 * k.assets_external / k.assets_total) : 0;
  const segC = LEVELS.map(l => ({ label: l, value: ctx[l] || 0, color: LV_COL[l] })), segS = ["critical", "high", "medium", "low", "unknown"].map(l => ({ label: l, value: sev[l] || 0, color: LV_COL[l] }));
  const actIc = { anomaly: "intelligence", investigation: "investigations" };
  m.innerHTML = ph("Security posture", "Attack surface, contextual risk and machine-learning-detected change across your infrastructure.",
    `<span class="mut" title="${ts(d.generated_at)} UTC">Updated ${esc(ago(d.generated_at))}</span><button class="btn sm" data-act="retry">${ic("refresh", "sm")}Refresh</button>`) + `
  ${!k.assets_total ? callout("info", 'No assets recorded. Configure discovery or import source data in <a href="#/integrations">Integrations</a>.') : ""}
  ${callout("info", `${d.freshness.not_recently_assessed} assets not recently assessed · ${d.freshness.no_vulnerability_detected} with no vulnerability detected within the assessment scope · threshold ${d.freshness.assessment_age_hours} hours · ${d.freshness.assets_with_conflicts} with conflicting evidence`)}
  <div class="kpis">${kpi("Assets", k.assets_total, "assets", { icon: "assets", sub: `${k.new_assets_24h ?? 0} new in 24h` })}${kpi("Externally exposed", k.assets_external, "assets?exposure=external", { icon: "globe", sub: `${pct}% of inventory`, cls: k.assets_external ? "k-high" : "" })}${kpi("Open findings", k.open_findings, "findings", { icon: "findings", sub: `${k.vulnerabilities} unique CVEs` })}${kpi("Critical / high", k.critical_high_findings, "findings?level=critical,high", { icon: "alert", cls: k.critical_high_findings ? "k-crit" : "", sub: "contextual risk" })}${kpi("Anomalies", k.anomalies_open, "intelligence/anomalies", { icon: "intelligence", sub: "awaiting review", cls: k.anomalies_open ? "k-acc" : "" })}${kpi("Open investigations", k.investigations_open, "investigations", { icon: "investigations", sub: "not yet closed" })}</div>
  <div class="strip"><a href="#/assets?status=active"><b>${k.assets_active}</b><span>Active assets</span></a><a href="#/intelligence/identity"><b>${k.assets_unresolved}</b><span>Unresolved identities</span></a><a href="#/findings"><b>${k.vulnerabilities}</b><span>Vulnerabilities (CVEs)</span></a><a href="#/infrastructure"><b>${k.changes_24h}</b><span>Changes (24h)</span></a><a href="#/intelligence/identity"><b>${k.identity_pending ?? 0}</b><span>Identity decisions pending</span></a></div>
  <div class="g21"><div>${panel("Top contextual risks", table(["Asset", "CVE", "CVSS", "Contextual risk", "Basis"], d.top_risks.map(r => ({ id: r.finding_id, cells: [`<span class="primary">${esc(r.asset)}</span>`, `<span class="mono">${esc(r.cve)}</span>${kevBadge(r.kev)}`, num(r.cvss, 1), scoreCell(r.contextual_score, r.level), basis(r.basis)] })), r => "findings/" + r.id, { empty: empty("shieldok", "No open findings", "Nothing is currently ranked.") }), '<a href="#/findings">All findings →</a>')}</div>
  <div>${panel("Risk distribution", pb(`<div class="donutwrap">${donut(segC, "open findings")}${legend(segC)}</div>`), "DEEPSIGHT contextual risk")}
  ${panel("Published vs contextual", pb(`<div class="lbl"><span>Published CVSS severity</span></div>${stackbar(segS)}<div class="pills" style="margin:8px 0 16px">${segS.filter(s => s.value).map(s => `<span class="pill"><span style="color:${s.color}">●</span> ${s.label} ${s.value}</span>`).join("") || '<span class="mut">none</span>'}</div><div class="lbl"><span>DEEPSIGHT contextual risk</span></div>${stackbar(segC)}<div class="pills" style="margin:8px 0 0">${segC.filter(s => s.value).map(s => `<span class="pill"><span style="color:${s.color}">●</span> ${s.label} ${s.value}</span>`).join("") || '<span class="mut">none</span>'}</div><div class="hint" style="margin-top:12px">Contextual risk adds exposure, asset criticality, KEV status, dependencies and evidence confidence to the published score.</div>`))}</div></div>
  <div class="g2">${panel("Assets by type", pb(bars(d.assets_by_type)))}${panel("Assets by risk level", pb(bars(d.assets_by_risk, true)))}</div>
  <div class="g2">${panel("Trends · 14 days", pb(`<div class="chartcap"><span>Open findings</span><b>${d.trend.open_findings.slice(-1)[0] ?? 0}</b></div>${lineChart(d.trend.days, d.trend.open_findings, "#f2893d", "Open findings")}<div class="chartcap" style="margin-top:14px"><span>Infrastructure changes</span><b>${d.trend.changes.reduce((a, b) => a + b, 0)} total</b></div>${lineChart(d.trend.days, d.trend.changes, "#38bdd0", "Changes")}`))}
  ${panel("Recent activity", pb(d.activity.length ? `<div class="tl">${d.activity.slice(0, 12).map(a => `<div class="ev k-${a.type === "anomaly" ? "anomaly" : a.type === "investigation" ? "investigation" : "change"}"><div class="t1">${when(a.ts)}${a.type === "anomaly" ? badge("anomaly", "predicted") : ""}${a.type === "investigation" ? badge("investigation", "analyst") : ""}${a.asset_id ? link("assets/" + a.asset_id, a.asset) : ""}</div><div class="t2">${esc(a.text)}</div></div>`).join("")}</div>` : empty("activity", "No recent activity")))}</div>`;

};
const STATUSES = ["active", "changed", "discovered", "inactive", "unreachable", "unresolved"], IDSTAT = ["confirmed", "probable", "inferred", "unresolved"];
const ATYPES = ["server", "workstation", "network_device", "cloud_resource", "virtual_machine", "container", "iot_device", "unknown"];
P.assets = async (m, id) => {
  if (id) return assetDetail(m, id);
  const p = qs(), keys = ["q", "type", "status", "exposure", "identity", "risk"];
  const f = keys.map(k => p.get(k) ? `${k}=${encodeURIComponent(p.get(k))}` : "").filter(Boolean).join("&");
  const page = pageNumber(p), size = 50;
  const d = await api(`/assets?size=${size}&page=${page}&` + f);
  const opt = (arr, key, all) => `<select name="${key}" aria-label="${all}"><option value="">${all}</option>${arr.map(t => `<option value="${t}" ${p.get(key) === t ? "selected" : ""}>${esc(human(t))}</option>`).join("")}</select>`;
  const chips = keys.filter(k => p.get(k)).map(k => { const q = new URLSearchParams(p); q.delete(k); return `<span class="chip rm">${esc(k)}: <b>${esc(p.get(k))}</b><a href="#/assets${q.toString() ? "?" + q : ""}" aria-label="Remove filter ${esc(k)}">${ic("x", "sm")}</a></span>`; }).join("");
  const cols = [{ h: "Asset", key: x => x.name.toLowerCase() }, { h: "IP address", key: x => x.ips[0] || "" }, { h: "Operating system", key: x => x.os || "" }, { h: "Findings", key: "open_findings" }, { h: "Risk", key: "risk_score" }, { h: "Identity", key: "identity_confidence" }, { h: "Status", key: "status" }, { h: "Last seen", key: "last_seen" }];
  m.innerHTML = ph(`Assets <span class="count">${d.total}</span>`, "Every asset DEEPSIGHT has resolved from connected sources, with exposure and contextual risk.") + `
  <form class="fbar" id="ff"><div class="search">${ic("search")}<input name="q" placeholder="Search name, IP, MAC, owner" value="${esc(p.get("q"))}" aria-label="Search assets"></div>${opt(ATYPES, "type", "All types")}${opt(STATUSES, "status", "Any status")}${opt(["external", "internal"], "exposure", "Any exposure")}${opt(["critical", "high", "medium", "low", "verify"], "risk", "Any risk")}${opt(IDSTAT, "identity", "Any identity")}<button class="btn pri">${ic("search", "sm")}Filter</button>${chips ? `<a class="btn ghost sm" href="#/assets">Clear all</a>` : ""}</form>${chips ? `<div class="chips" style="margin:-4px 0 14px">${chips}</div>` : ""}
  ${panel("", stable("assets", cols, d.items, a => ({ id: a.id, cells: [`<div class="nowrap">${typeIc(a.type)} <span class="primary">${esc(a.name)}</span>${a.exposure === "external" ? ' <span class="badge ext">external</span>' : ""}</div><div class="secondary">${esc(human(a.type))}${a.owner ? " · " + esc(a.owner) : ""} · criticality ${a.criticality}</div>`, `<span class="mono">${a.ips.length ? esc(a.ips.slice(0, 2).join(", ")) + (a.ips.length > 2 ? ` <span class="mut">+${a.ips.length - 2}</span>` : "") : '<span class="mut">–</span>'}</span>`, a.os ? `<div style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(a.os)}">${esc(a.os)}</div>` : '<span class="mut">–</span>', a.open_findings ? `<b class="num">${a.open_findings}</b>` : `<span class="mut">${esc(human(a.freshness.assessment_state))}</span>`, scoreCell(a.risk_score, a.risk_level), `${badge(a.identity_status, a.identity_status === "confirmed" ? "ok" : a.identity_status === "probable" ? "warn" : "neutral")}<div class="secondary num" title="identity confidence">${num(a.identity_confidence)}</div>`, badge(a.status, a.status === "active" ? "ok" : a.status === "changed" ? "warn" : "neutral"), when(a.last_seen)] }), r => "assets/" + r.id, { i: 4, dir: -1 }, { note: d.total > size ? "Sorting applies to this page" : "", empty: empty("assets", "No assets match these filters", "Adjust or clear the filters, or import data from Integrations.") }))}${pageLinks("assets", p, d.total, page, size)}`;
  const ff = $("#ff", m); ff.onsubmit = e => { e.preventDefault(); const u = new URLSearchParams(); for (const [k, v] of new FormData(ff)) if (v) u.set(k, v); location.hash = "#/assets" + (u.toString() ? "?" + u : ""); };
  $$("select", ff).forEach(s => s.onchange = () => ff.requestSubmit());
};
async function assetDetail(m, id) {
  const a = await api("/assets/" + id); S.ctx = { page: "asset", asset_id: +id };
  const tab = S.tab.asset || "overview";
  const RISKY = { 21: "cleartext FTP", 23: "cleartext Telnet", 1883: "MQTT without TLS", 2323: "alt Telnet", 554: "RTSP stream", 9100: "raw print port", 8291: "Winbox admin" };
  const T = ["overview", "identifiers", "observations", "services", "vulnerabilities", "relationships", "history", "risk"];
  const counts = { identifiers: a.identifiers.length, observations: a.observations.length, services: a.services.length, vulnerabilities: a.findings.length, relationships: a.relationships.length, history: a.history.length };
  const idv = k => a.identifiers.filter(i => i.kind === k && i.active).map(i => i.value);
  const pills = (arr, mono) => arr.length ? `<div class="pills">${arr.map(x => `<span class="pill ${mono ? "mono" : ""}">${esc(x)}</span>`).join("")}</div>` : '<span class="mut">–</span>';
  const factors = a.risk_history[0]?.factors || [];
  const body = {
    overview: () => `<div class="g2"><div>${panel("Asset profile", pb(`<div class="kv"><div>Type</div><div>${typeIc(a.type)} ${esc(human(a.type))}</div><div>Status</div><div>${esc(a.status)}</div><div>Operating system</div><div>${esc(a.os) || '<span class="mut">Not reported by a source</span>'}</div><div>Owner</div><div>${esc(a.owner) || '<span class="mut">Import owner information from inventory</span>'}</div><div>Hostnames</div><div>${pills(idv("hostname"), 1)}</div><div>IP addresses</div><div>${pills(a.ips.length ? a.ips : idv("ip"), 1)}</div><div>MAC addresses</div><div>${pills(idv("mac"), 1)}</div><div>Identity</div><div>${esc(a.identity_status)} <span class="mut">(confidence ${num(a.identity_confidence)})</span></div><div>First / last seen</div><div>${ts(a.first_seen)} / ${ts(a.last_seen)}</div>${a.tags?.length ? `<div>Tags</div><div>${pills(a.tags)}</div>` : ""}</div>`))}</div>
      <div>${panel("Contextual risk", pb(`<div style="display:flex;align-items:baseline;gap:12px"><span style="font-size:34px;font-weight:600">${num(a.risk_score, 0)}</span>${lv(a.risk_level)}<span class="mut">confidence ${num(a.risk_confidence)}</span></div><div class="meter ${esc(a.risk_level)}" style="margin:10px 0 14px"><i style="width:${Math.min(100, a.risk_score || 0)}%"></i></div>${factors.map(f => `<div class="hbar" style="grid-template-columns:minmax(120px,210px) 1fr 40px"><span class="k" style="text-transform:none;white-space:normal" title="${esc(f.label)}">${esc(f.label)}</span><div class="meter"><i style="width:${Math.min(100, f.contribution * 40)}%"></i></div><span class="v mut">${num(f.value)}</span></div>`).join("") || '<span class="mut">No factor breakdown recorded.</span>'}<div class="hint" style="margin-top:10px">Anomalies: ${a.anomalies.map(x => `${esc(x.status)} ${num(x.score)}`).join(", ") || "none"}</div>`), "explainable score")}</div></div>
      ${panel("Impact if compromised", pb(`<div class="g3" style="margin:0">${["hosted_on_this", "dependents", "reachable_dependencies"].map(k => `<div><div class="lbl"><span>${esc(human(k))}</span></div>${a.impact[k].length ? `<div class="stack">${a.impact[k].map(x => `<div>${link("assets/" + x.asset_id, x.name)}</div>`).join("")}</div>` : '<span class="mut">none</span>'}</div>`).join("")}</div>`))}`,
    identifiers: () => table(["Kind", "Value", "Active", "Source", "First", "Last"], a.identifiers.map(i => ({ cells: [esc(i.kind), `<span class="mono">${esc(i.value)}</span>`, i.active ? badge("active", "ok") : badge("inactive", "neutral"), esc(i.source), when(i.first_seen), when(i.last_seen)] }))) + `<div class="sect" style="padding:0 16px">Identity decisions</div>` + table(["#", "Outcome", "Status", "Confidence", "Evidence"], a.identity_decisions.map(d => ({ cells: [d.id, esc(d.outcome), esc(d.status), num(d.confidence), `<div class="wrap">${esc((d.evidence || []).join("; "))}</div>`] })), null, { empty: empty("merge", "No identity decisions") }),
    observations: () => table(["#", "Source", "Observed", "Status", "Match", "Quality", "Flags"], a.observations.map(o => ({ id: o.id, cells: [o.id, esc(o.source), when(o.observed_at), esc(o.status), esc(o.match_outcome) + " " + num(o.match_confidence), num(o.quality_score), (o.flags || []).map(f => badge(f, "warn")).join(" ")] })), r => "obs/" + r.id),
    services: () => table(["Port", "Service", "Product", "Version", "Exposed", "Active", "Source", "First seen"], a.services.map(s => ({ cells: [`<span class="mono">${s.port}/${esc(s.proto)}</span>${RISKY[s.port] ? ` <span class="badge high" title="${esc(RISKY[s.port])}">${esc(RISKY[s.port])}</span>` : ""}`, esc(s.name), esc(s.product), esc(s.version), s.exposed ? '<span class="badge ext">external</span>' : '<span class="mut">no</span>', s.active ? badge("active", "ok") : badge("closed", "neutral"), esc(s.source), when(s.first_seen)] })), null, { empty: empty("server", "No services recorded") }) + `<div class="sect" style="padding:0 16px">Software</div>` + table(["Product", "Version", "Active"], a.software.map(s => ({ cells: [esc(s.product), esc(s.version), s.active ? badge("active", "ok") : badge("inactive", "neutral")] })), null, { empty: empty("file", "No software recorded") }),
    vulnerabilities: () => findTable(a.findings, "assetfind"),
    relationships: () => table(["Direction", "Type", "Asset", "Basis", "Confidence", "Active"], a.relationships.map(r => ({ cells: [r.direction === "out" ? "outbound →" : "← inbound", esc(human(r.type)), link("assets/" + r.other_id, r.other_name), basis(r.basis), num(r.confidence), r.active ? badge("active", "ok") : badge("closed", "neutral")] })), null, { empty: empty("infrastructure", "No relationships") }),
    history: () => table(["Time", "Change", "Summary"], a.history.map(h => ({ cells: [when(h.ts), badge(human(h.kind), "neutral"), esc(h.summary)] })), null, { empty: empty("history", "No history") }),
    risk: () => table(["Time", "Score", "Level", "Confidence", "Summary"], a.risk_history.map(r => ({ cells: [when(r.ts), num(r.score, 0), lv(r.level), num(r.confidence), `<div class="wrap">${esc(r.summary)}</div>`] }))) + `<div class="pager">Risk model ${esc(a.risk_history[0]?.version)}: an explainable weighted score, not a probability of compromise.</div>`,
  };
  const stat = (l, v) => `<div><span>${l}</span><b style="display:block;margin-top:2px;font-weight:600">${v}</b></div>`;
  m.innerHTML = ph(`${typeIc(a.type)} ${esc(a.name)} ${badge(human(a.type), "neutral")}${a.exposure === "external" ? ' <span class="badge ext">external</span>' : ""}`, `${esc(a.primary_identifier || "")}`, WRITE() ? `<button class="btn" data-act="inv-asset" data-id="${a.id}">${ic("investigations", "sm")}Start investigation</button>` : "", `<a href="#/assets">Assets</a> / ${esc(a.name)}`) +
    `<div class="strip">${stat("Contextual risk", `${num(a.risk_score, 0)} ${lv(a.risk_level)}`)}${stat("Criticality", `${a.criticality} ${WRITE() ? `<select data-crit="${a.id}" aria-label="Criticality" style="padding:2px 24px 2px 8px">${[1, 2, 3, 4, 5].map(n => `<option ${n === a.criticality ? "selected" : ""}>${n}</option>`).join("")}</select>` : ""}`)}${stat("Open findings", a.open_findings)}${stat("Identity", esc(a.identity_status))}${stat("Last seen", when(a.last_seen))}</div>
    ${panel("Data freshness and source coverage", pb(freshnessView(a.freshness)))}
    <div class="tabs" role="tablist">${T.map(t => `<button role="tab" data-tab="asset:${t}" aria-selected="${t === tab}" tabindex="${t === tab ? 0 : -1}" class="${t === tab ? "on" : ""}">${t}${counts[t] != null ? `<span class="n">${counts[t]}</span>` : ""}</button>`).join("")}</div>${tab === "overview" ? body[tab]() : panel("", body[tab]())}`;
}
const findCols = [{ h: "Finding code", key: "cve" }, { h: "Asset", key: x => (x.asset || "").toLowerCase() }, { h: "CVSS (published)", key: "cvss" }, { h: "Contextual risk", key: "contextual_score" }, { h: "Conf.", key: "confidence" }, { h: "Exposure", key: "exposure" }, { h: "Basis", key: "basis" }, { h: "Status", key: "investigation_status" }];
const findRow = f => ({ id: f.id, cells: [`<span class="mono primary">${esc(f.cve)}</span>${kevBadge(f.kev)}${f.title ? `<div class="secondary" style="max-width:300px;white-space:normal">${esc(f.title)}</div>` : ""}`, esc(f.asset), cvssBadge(f.cvss, f.severity), scoreCell(f.contextual_score, f.contextual_level), `<span class="num">${num(f.confidence)}</span>`, f.exposure === "external" ? '<span class="badge ext">external</span>' : '<span class="mut">internal</span>', basis(f.basis), badge(human(f.investigation_status), f.investigation_status === "new" ? "neutral" : "info")] });
const findTable = (rows, id = "finds", def = { i: 3, dir: -1 }) => stable(id, findCols, rows, findRow, r => "findings/" + r.id, def, { match: f => `${f.cve} ${f.asset} ${f.title || ""}`, empty: empty("shieldok", "No findings", "No open findings match.") });
P.obs = async (m, id) => {
  const o = await api("/observations/" + id);
  m.innerHTML = ph(`Observation #${o.id}`, "Normalized record and the raw source data it came from.", "", `<a href="#/assets">Assets</a> / observation`) + panel("Summary", pb(`<div class="kv"><div>Source</div><div>${esc(o.source)}</div><div>Observed</div><div>${ts(o.observed_at)}</div><div>Status</div><div>${esc(o.status)} ${esc(o.match_outcome)} ${num(o.match_confidence)}</div><div>Quality</div><div>${num(o.quality_score)} ${(o.quality.flags || []).map(f => badge(f, "warn")).join(" ")}</div></div>`)) +
    `<div class="g2">${panel("Normalized", pb(jsonView({ identifiers: o.identifiers, attributes: o.attributes })))}${panel("Raw source record", pb(jsonView(o.raw)))}</div>`;
};
P.findings = async (m, id) => {
  if (id) return findingDetail(m, id);
  const p = qs(), lvl = p.get("level"), kev = p.get("kev"), page = pageNumber(p), size = 50;
  const query = new URLSearchParams(p); query.set("size", size); query.set("page", page);
  const d = await api("/findings?" + query);
  // Search is performed over all matching findings before pagination.
  S.q.finds = "";
  const chip = (level, known, label) => {
    const q = new URLSearchParams(p); q.delete("page"); q.delete("level"); q.delete("kev");
    if (level) q.set("level", level); if (known) q.set("kev", "true");
    return `<a class="chip ${(lvl || "") === level && !!kev === known ? "on" : ""}" href="#/findings${q.size ? "?" + q : ""}">${label}</a>`;
  };
  m.innerHTML = ph(`Findings <span class="count">${d.total}</span>`, "CVE and configuration findings matched to assets. Published CVSS severity is shown beside DEEPSIGHT's contextual risk assessment.") +
    `<div class="fbar"><div class="chips">${chip("", false, "All")}${chip("critical,high", false, "Critical / high")}${chip("critical", false, "Critical")}${chip("high", false, "High")}${chip("", true, "Known exploited")}</div><form id="find-search" class="find-search"><div class="search">${ic("search")}<input name="q" placeholder="Search CVE, asset or title" value="${esc(p.get("q") || "")}" aria-label="Search findings"></div><button class="btn">Search</button></form></div>
    ${panel("", findTable(d.items, "finds"))}${pageLinks("findings", p, d.total, page, size)}${callout("info", "Contextual risk differs from CVSS: it includes exposure, criticality, KEV, dependencies and evidence confidence.")}`;
  $("#find-search", m).onsubmit = e => { e.preventDefault(); const q = new URLSearchParams(p); q.delete("page"); const value = new FormData(e.target).get("q").trim(); if (value) q.set("q", value); else q.delete("q"); location.hash = "#/findings" + (q.size ? "?" + q : ""); };

};
async function findingDetail(m, id) {
  const f = await api("/findings/" + id), a = f.assessment, fac = a ? a.factors : [];
  const ast = f.asset_summary || {};
  m.innerHTML = ph(`<span class="mono">${esc(f.cve)}</span> ${kevBadge(f.kev)} ${basis(f.basis)}`, esc(f.title || ""), WRITE() ? `<button class="btn" data-act="inv-finding" data-id="${f.id}">${ic("investigations", "sm")}Start investigation</button>` : "", `<a href="#/findings">Findings</a> / ${esc(f.cve)} on ${link("assets/" + f.asset_id, f.asset)}`) + `
  <div class="g2"><div>${panel(f.kind === "configuration" ? "Configuration policy" : "Published vulnerability data", pb(`<div style="display:flex;align-items:baseline;gap:12px;margin-bottom:12px"><span style="font-size:34px;font-weight:600">${f.cvss == null ? "Not assigned" : num(f.cvss, 1)}</span><span class="mut">CVSS</span><span class="badge ${sevCls(f.severity)}">${esc(f.severity || "unknown")}</span></div><p style="margin:0 0 14px;color:var(--tx2)">${esc(f.description)}</p><div class="kv"><div>Known exploited</div><div>${f.kev ? 'yes (CISA KEV) <span class="badge kev">KEV</span>' : "no"}</div><div>Exploit available</div><div>${f.exploit_available ? "yes" : "not recorded"}</div><div>ATT&amp;CK</div><div>${(f.techniques || []).length ? `<div class="pills">${f.techniques.map(t => `<span class="pill mono">${esc(t)}</span>`).join("")}</div>` : '<span class="mut">–</span>'}</div><div>Catalog source</div><div>${esc(f.vuln_source || "–")}</div><div>First / last seen</div><div>${ts(f.first_seen)} / ${ts(f.last_seen)}</div></div>`), f.kind === "configuration" ? "Policy inference; no CVSS assigned" : "what the vendor/NVD says")}</div>
  <div>${panel("DEEPSIGHT contextual assessment", pb(`<div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap"><span style="font-size:34px;font-weight:600">${a ? num(a.score, 0) : "–"}</span>${a ? lv(a.level) : ""}<span class="mut">confidence ${a ? num(a.confidence) : "–"} · ${a ? esc(a.version) : ""}</span></div>${a ? `<div class="meter ${esc(a.level)}" style="margin:10px 0 14px"><i style="width:${Math.min(100, a.score)}%"></i></div>` : ""}${fac.map(x => `<div class="hbar" style="grid-template-columns:minmax(120px,200px) 1fr 40px"><span class="k" style="text-transform:none;white-space:normal" title="${esc(x.label)}">${esc(x.label)}</span><div class="meter"><i style="width:${Math.min(100, x.contribution * 35)}%"></i></div><span class="v mut">${num(x.value)}</span></div>`).join("")}<div class="hint" style="margin-top:10px">Bars show each factor's contribution to the score; the number is the factor value. This is an explainable weighted score, not a probability of compromise.</div>`), "explainable, context-aware")}</div></div>
  <div class="g2">${panel("Affected asset", pb(`<div class="kv"><div>Asset</div><div>${link("assets/" + f.asset_id, f.asset)}</div><div>Type</div><div>${esc(human(ast.type))}</div><div>Exposure</div><div>${esc(f.exposure)}</div><div>Criticality</div><div>${esc(f.asset_criticality ?? ast.criticality ?? "–")}</div><div>Service</div><div>${f.service ? esc(f.service.product + " " + (f.service.version || "") + " :" + f.service.port) + (f.service.exposed ? ' <span class="badge ext">external</span>' : "") : '<span class="mut">–</span>'}</div><div>Triage</div><div>${esc(f.triage.state)} ${esc(f.triage.note)}</div></div>`))}
  ${panel("Why it matters / suggested actions", pb((f.suggested_actions || []).length ? `<ul class="list">${f.suggested_actions.map(x => `<li>${ic("chev", "sm")}<span>${esc(x)}</span></li>`).join("")}</ul>` : '<span class="mut">none</span>'))}</div>
  ${panel("Assessment freshness", pb(freshnessView(f.freshness)))}
  ${panel("Evidence", pb(jsonView(f.evidence, "evj")), "how this finding was matched")}
  ${(f.assessment_history || []).length > 1 ? panel("Score history", table(["Time", "Score", "Level"], f.assessment_history.map(h => ({ cells: [when(h.ts), num(h.score, 0), lv(h.level)] })))) : ""}
  ${WRITE() ? panel("Remediation workflow", pb(`<form id="remediation-form" class="stack">
    <label>Status <select name="state">${["new", "confirmed", "in_progress", "pending_verification", "accepted_risk", "false_positive"].map(v => `<option ${v === f.workflow.state ? "selected" : ""}>${v}</option>`).join("")}</select></label>
    ${[["owner","Owner"],["due_date","Due date (ISO date)"],["remediation_guidance","Remediation guidance"],["ticket_reference","Ticket URL"],["reason","Reason"],["approver","Approver (recorded analyst assertion)"],["expiry","Exception expiry (ISO date)"]].map(([k,l]) => `<label>${l}<input name="${k}" value="${esc(f.workflow[k] || (k === "remediation_guidance" ? f.remediation : "") || "")}"></label>`).join("")}
    <button class="btn pri">Save workflow</button></form><p class="hint">Accepted risk and false positive need a reason, approver and future expiry. They do not count as verified fixes.</p>
    <form id="verify-form" class="fbar"><label>Verification observation ID <input name="observation_id" type="number" min="1" required></label><button class="btn">Verify and close</button></form><button class="btn" id="what-if">What if this finding is fixed?</button><div id="what-if-result"></div>`)) : ""}`;
  const wf = $("#remediation-form", m);
  if (wf) wf.onsubmit = async e => { e.preventDefault(); try { await api("/findings/" + id, {method:"PATCH", body:Object.fromEntries(new FormData(wf))}); toast("Workflow saved", "ok"); render(); } catch(e) {toast(e.message,"warn");} };
  const vf = $("#verify-form", m);
  if (vf) vf.onsubmit = async e => {e.preventDefault(); try {await api(`/findings/${id}/verify`,{method:"POST",body:{observation_id:+new FormData(vf).get("observation_id")}});toast("Verification evidence stored", "ok");render();}catch(e){toast(e.message,"warn");}};
  const wi = $("#what-if", m);
  if (wi) wi.onclick = async () => {try {$("#what-if-result",m).innerHTML=jsonView(await api(`/findings/${id}/what-if`));}catch(e){toast(e.message,"warn");}};
  S.ctx = { page: "finding", asset_id: f.asset_id, finding_id: +id };
}

// ---- infrastructure graph
let GR = null;
P.infrastructure = async m => {
  const [g, ch] = await Promise.all([api("/graph"), api("/changes?hours=168&limit=60")]);
  const W = 900, H = 540, N = g.nodes.map((n, i) => ({ ...n, x: W / 2 + 250 * Math.cos(i * 2.4), y: H / 2 + 190 * Math.sin(i * 2.4), vx: 0, vy: 0 })), ix = Object.fromEntries(N.map(n => [n.id, n]));
  for (let it = 0; it < 220; it++) {
    for (const a of N) for (const b of N) if (a !== b) { const dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 1, f = 2600 / d2, d = Math.sqrt(d2); a.vx += dx * f / d; a.vy += dy * f / d; }
    for (const e of g.edges) { const a = ix[e.source], b = ix[e.target]; if (!a || !b) continue; const dx = b.x - a.x, dy = b.y - a.y; a.vx += dx * .01; a.vy += dy * .01; b.vx -= dx * .01; b.vy -= dy * .01; }
    for (const n of N) { n.vx += (W / 2 - n.x) * .002; n.vy += (H / 2 - n.y) * .002; n.x = Math.max(30, Math.min(W - 30, n.x + n.vx * .5)); n.y = Math.max(25, Math.min(H - 25, n.y + n.vy * .5)); n.vx *= .6; n.vy *= .6; }
  }
  const edges = g.edges.filter(e => ix[e.source] && ix[e.target]), deg = {};
  edges.forEach(e => { deg[e.source] = (deg[e.source] || 0) + 1; deg[e.target] = (deg[e.target] || 0) + 1; });
  const nodes = N.filter(n => deg[n.id]);
  if (nodes.length > 1) {   // presentation only: stretch the computed layout to use the whole canvas (labels need room on the right)
    const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y), x0 = Math.min(...xs), y0 = Math.min(...ys), bw = Math.max(1, Math.max(...xs) - x0), bh = Math.max(1, Math.max(...ys) - y0), k = Math.min(3, (W - 230) / bw, (H - 90) / bh), ox = 40 + (W - 230 - bw * k) / 2, oy = (H - bh * k) / 2;
    nodes.forEach(n => { n.x = ox + (n.x - x0) * k; n.y = oy + (n.y - y0) * k; });
  }
  GR = { nodes, edges, ix, deg, W, H };
  const bcls = b => b === "observed" ? "observed" : b === "inferred" ? "inferred" : "other", rad = n => 6 + Math.min(5, deg[n.id] || 0);
  const edgeSvg = edges.map((e, i) => { const a = ix[e.source], b = ix[e.target], dx = b.x - a.x, dy = b.y - a.y, L = Math.hypot(dx, dy) || 1, r = rad(b) + 3;
    const x2 = b.x - dx / L * r, y2 = b.y - dy / L * r, c = bcls(e.basis);
    return `<g class="ge ${c}" data-e="${i}"><path class="gedge ${c}" d="M${a.x.toFixed(1)} ${a.y.toFixed(1)}L${x2.toFixed(1)} ${y2.toFixed(1)}" marker-end="url(#ar-${c})"/><text class="elab" x="${((a.x + b.x) / 2).toFixed(1)}" y="${((a.y + b.y) / 2 - 3).toFixed(1)}" text-anchor="middle">${esc(human(e.type))}</text><title>${esc(human(e.type))} (${esc(e.basis)}, confidence ${num(e.confidence)})</title></g>`; }).join("");
  const nodeSvg = nodes.map(n => `<g class="gnode" data-n="${n.id}" tabindex="0" role="button" aria-label="${esc(n.name)}"><circle cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="${rad(n)}" fill="${LV_COL[n.risk_level] || "#64748b"}" stroke="${n.exposure === "external" ? "#fff" : "#070a0f"}"/><text x="${(n.x + rad(n) + 4).toFixed(1)}" y="${(n.y + 4).toFixed(1)}">${esc(n.name.length > 24 ? n.name.slice(0, 23) + "…" : n.name)}</text><title>${esc(n.name)} · ${esc(human(n.type))} · risk ${esc(n.risk_level)}${n.exposure === "external" ? " · external" : ""}</title></g>`).join("");
  const mk = (c, col) => `<marker id="ar-${c}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="${col}"/></marker>`;
  const nb = edges.filter(e => e.basis === "observed").length, ni = edges.filter(e => e.basis === "inferred").length;
  m.innerHTML = ph("Infrastructure", "How assets depend on, host and connect to each other. Select a node to inspect its relationships.") + panel("", `<div class="graphwrap"><div class="graph">${nodes.length ? `<div class="gt"><input id="gq" placeholder="Find asset…" aria-label="Find asset in graph" autocomplete="off"><button class="btn sm" data-g="labels" aria-pressed="false">Edge labels</button><button class="btn sm" data-g="inferred" aria-pressed="true">Inferred links</button></div>
    <svg id="gsvg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Asset relationship graph"><defs>${mk("observed", "#5b8bd0")}${mk("inferred", "#e6b73a")}${mk("other", "#b78cf2")}</defs>${edgeSvg}${nodeSvg}</svg>
    <div class="zb"><button class="iconbtn" data-g="zin" title="Zoom in" aria-label="Zoom in">${ic("zoomin")}</button><button class="iconbtn" data-g="zout" title="Zoom out" aria-label="Zoom out">${ic("zoomout")}</button><button class="iconbtn" data-g="fit" title="Reset view" aria-label="Reset view">${ic("fit")}</button></div>` : empty("infrastructure", "No relationships to draw", "Connected assets appear here once relationships are observed or inferred.")}</div>
    <aside class="gside" id="gside"></aside></div><div class="gl-legend"><span><i style="background:${LV_COL.critical}"></i>critical</span><span><i style="background:${LV_COL.high}"></i>high</span><span><i style="background:${LV_COL.medium}"></i>medium</span><span><i style="background:${LV_COL.low}"></i>low</span><span><i style="background:${LV_COL.verify}"></i>verify</span><span><i style="background:#0a0f1c;border:2px solid #fff;width:8px;height:8px"></i>externally exposed</span><span><u style="border-color:#5b8bd0"></u>observed</span><span><u style="border-color:#e6b73a;border-top-style:dashed"></u>inferred</span><span class="mut" style="margin-left:auto">Colour = contextual risk · drag to pan · Ctrl + scroll to zoom · double-click a node to open the asset</span></div>`) +
    `<div class="sect">Changes · last 7 days</div>` + panel("", table(["Time", "Asset", "Change", "Summary"], ch.filter(c => !["identifier_added", "relationship_added", "asset_created"].includes(c.kind)).map(c => ({ cells: [when(c.ts), link("assets/" + c.asset_id, c.asset), badge(human(c.kind), "neutral"), `<div class="wrap">${esc(c.summary)}</div>`] })), null, { empty: empty("history", "No changes in the last 7 days") }));
  GR.nb = nb; GR.ni = ni;
};
P.infrastructure.after = pg => {
  if (!GR) return; const svg = $("#gsvg", pg), side = $("#gside", pg); const { W, H } = GR; const V = { x: 0, y: 0, w: W, h: H };
  const setV = () => svg && svg.setAttribute("viewBox", `${V.x.toFixed(1)} ${V.y.toFixed(1)} ${V.w.toFixed(1)} ${V.h.toFixed(1)}`);
  const zoom = (f, cx, cy) => { const nw = Math.max(W * .25, Math.min(W * 2, V.w * f)), k = nw / V.w; cx = cx ?? V.x + V.w / 2; cy = cy ?? V.y + V.h / 2; V.x = cx - (cx - V.x) * k; V.y = cy - (cy - V.y) * k; V.w = nw; V.h = nw * H / W; setV(); };
  const summary = () => `<h3 style="font-size:14px;margin-bottom:10px">Relationship graph</h3><div class="kv"><div>Connected assets</div><div>${GR.nodes.length}</div><div>Relationships</div><div>${GR.edges.length}</div><div>Observed</div><div>${GR.nb} ${basis("observed")}</div><div>Inferred</div><div>${GR.ni} ${basis("inferred")}</div></div><div class="callout">${ic("info")}<div>Observed relationships come directly from source data. Inferred ones are derived by DEEPSIGHT and carry a confidence value. Select a node to see them.</div></div>`;
  const nodePanel = id => { const n = GR.ix[id]; if (!n) return summary();
    const rel = GR.edges.filter(e => e.source === id || e.target === id);
    return `<div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">${typeIc(n.type)}<h3 style="font-size:15px;word-break:break-all">${esc(n.name)}</h3></div><div class="pills" style="margin-bottom:12px">${badge(human(n.type), "neutral")}${lv(n.risk_level)}${n.exposure === "external" ? '<span class="badge ext">external</span>' : ""}</div>
      <div class="kv" style="margin-bottom:12px"><div>Risk score</div><div>${num(n.risk_score, 0)}</div><div>Status</div><div>${esc(n.status)}</div></div><a class="btn sm" href="#/assets/${n.id}">Open asset ${ic("chev", "sm")}</a><div class="sect" style="margin-top:18px">Relationships (${rel.length})</div>
      ${rel.map(e => { const out = e.source === id, o = GR.ix[out ? e.target : e.source]; return `<div style="padding:7px 0;border-top:1px solid var(--line)"><div style="font-size:12px;color:var(--mut)">${out ? "→" : "←"} ${esc(human(e.type))} ${basis(e.basis)} <span class="num">${num(e.confidence)}</span></div><a href="#" data-gsel="${o.id}">${esc(o.name)}</a></div>`; }).join("")}`; };
  const sel = id => { S.gsel = id; if (!svg) return; const nb = new Set(); if (id != null) GR.edges.forEach(e => { if (e.source === id || e.target === id) { nb.add(e.source); nb.add(e.target); } });
    $$(".gnode", svg).forEach(g => { const n = +g.dataset.n; g.classList.toggle("sel", n === id); g.classList.toggle("dim", id != null && !nb.has(n)); });
    $$(".ge", svg).forEach(g => { const e = GR.edges[+g.dataset.e], on = id != null && (e.source === id || e.target === id); g.classList.toggle("hl", on); g.classList.toggle("dim", id != null && !on); });
    side.innerHTML = id != null ? nodePanel(id) : summary(); };
  side.innerHTML = summary(); if (!svg) return;
  pg.addEventListener("click", e => { const g = e.target.closest("[data-gsel]"); if (g) { e.preventDefault(); sel(+g.dataset.gsel); } const b = e.target.closest("[data-g]"); if (!b) return;
    const a = b.dataset.g; if (a === "zin") zoom(.8); if (a === "zout") zoom(1.25); if (a === "fit") { V.x = 0; V.y = 0; V.w = W; V.h = H; setV(); }
    if (a === "labels") { const on = svg.classList.toggle("lab"); b.setAttribute("aria-pressed", on); b.classList.toggle("pri", on); }
    if (a === "inferred") { const hide = svg.classList.toggle("hide-inf"); b.setAttribute("aria-pressed", !hide); b.classList.toggle("pri", !hide); } });
  let drag = null, moved = false;
  svg.addEventListener("pointerdown", e => { if (e.target.closest(".gnode")) return; drag = { x: e.clientX, y: e.clientY, vx: V.x, vy: V.y }; moved = false; svg.setPointerCapture(e.pointerId); });
  svg.addEventListener("pointermove", e => { if (!drag) return; const r = svg.getBoundingClientRect(), dx = e.clientX - drag.x, dy = e.clientY - drag.y; if (Math.abs(dx) + Math.abs(dy) > 4) { moved = true; svg.classList.add("drag"); } V.x = drag.vx - dx * V.w / r.width; V.y = drag.vy - dy * V.h / r.height; setV(); });
  svg.addEventListener("pointerup", () => { drag = null; svg.classList.remove("drag"); });
  svg.addEventListener("click", e => { const n = e.target.closest(".gnode"); if (n) sel(+n.dataset.n); else if (!moved) sel(null); });
  svg.addEventListener("dblclick", e => { const n = e.target.closest(".gnode"); if (n) location.hash = "#/assets/" + n.dataset.n; });
  svg.addEventListener("keydown", e => { const n = e.target.closest(".gnode"); if (n && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); sel(+n.dataset.n); } });
  svg.addEventListener("wheel", e => { if (!e.ctrlKey && !e.metaKey) return; e.preventDefault(); const r = svg.getBoundingClientRect(); zoom(e.deltaY > 0 ? 1.1 : .9, V.x + (e.clientX - r.left) / r.width * V.w, V.y + (e.clientY - r.top) / r.height * V.h); }, { passive: false });
  const gq = $("#gq", pg); if (gq) { gq.addEventListener("input", () => { const q = gq.value.trim().toLowerCase(); if (!q) return sel(S.gsel); $$(".gnode", svg).forEach(g => g.classList.toggle("dim", !GR.ix[+g.dataset.n].name.toLowerCase().includes(q))); });
    gq.addEventListener("keydown", e => { if (e.key === "Enter") { const n = GR.nodes.find(x => x.name.toLowerCase().includes(gq.value.trim().toLowerCase())); if (n) sel(n.id); } }); }
  if (S.gsel != null && GR.ix[S.gsel]) sel(S.gsel); else S.gsel = null;
};

// ---- intelligence
const MODEL_TITLE = { "entity-resolution": "Entity resolution (identity matching)", "anomaly-detection": "Anomaly detection", "contextual-risk": "Contextual risk scoring" };
P.intelligence = async (m, sub) => {
  sub = sub || "anomalies"; const tabs = ["anomalies", "identity", "models", "catalog"]; let body = "";
  if (sub === "anomalies") {
    const d = await api("/anomalies");
    body = table(["Time", "Asset", "Anomaly score vs threshold", "Status", "Explanation", ""], d.items.map(x => ({ cells: [when(x.ts), link("assets/" + x.asset_id, x.asset), `<div style="min-width:170px"><div class="meter" style="margin-bottom:5px"><i style="width:${Math.min(100, x.score * 100)}%;background:var(--pred)"></i><span class="mk" style="left:${Math.min(100, x.threshold * 100)}%" title="threshold ${num(x.threshold, 3)}"></span></div><span class="num">${num(x.score, 3)}</span> <span class="mut">/ ${num(x.threshold, 3)}</span> ${badge("predicted", "predicted")}</div>`, anomBadge(x.status), `<div class="wrap">${esc(x.summary)}${(x.contributors || []).length ? `<div class="pills" style="margin-top:6px">${x.contributors.map(c => `<span class="pill">${esc(c.label)}</span>`).join("")}</div>` : ""}</div>`, WRITE() ? `<div class="nowrap"><button class="btn sm" data-an="${x.id}:true_positive">True positive</button> <button class="btn sm" data-an="${x.id}:false_positive">False positive</button> <button class="btn sm ghost" data-an="${x.id}:reviewed">Reviewed</button></div>` : ""] })), null, { empty: empty("intelligence", "No anomalies detected", "The Isolation Forest model has not flagged unusual change on any asset.") }) +
      `<div class="pager">${esc(d.items[0]?.limitation || "An anomaly is a deviation from learned patterns, not proof of malicious activity.")}</div>`;
  }
  if (sub === "identity") {
    const d = await api("/identity/decisions?status=review");
    body = pb(d.items.length ? d.items.map(x => `<div class="dcard"><div class="dh"><b>#${x.id}</b>${badge(x.outcome, x.outcome === "probable" ? "warn" : "neutral")}${badge(x.status, x.status === "pending" ? "info" : "neutral")}<span class="mut" style="margin-left:auto">model ${esc(x.model_version || "–")}</span></div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px"><span class="mono primary">${esc(x.asset)}</span><span class="arrow">${ic("merge")}</span><span class="mono primary">${esc(x.candidate)}</span><span class="mut">observation → candidate asset</span></div>
      <div class="lbl"><span>Match confidence</span><span class="num">${num(x.confidence)}</span></div><div class="meter" style="margin-bottom:12px"><i style="width:${Math.min(100, x.confidence * 100)}%"></i></div>
      <div class="lbl"><span>Evidence</span></div>${(x.evidence || []).length ? `<ul class="list">${x.evidence.map(e => `<li>${ic("chev", "sm")}<span>${esc(e)}</span></li>`).join("")}</ul>` : '<span class="mut">none recorded</span>'}
      ${WRITE() ? `<div class="acts">${x.status === "pending" ? `<button class="btn pri" data-id-act="${x.id}:confirm">${ic("merge", "sm")}Same asset (merge)</button><button class="btn" data-id-act="${x.id}:reject">Separate</button>` : `<button class="btn" data-id-act="${x.id}:revert">Revert decision</button>`}</div>` : ""}</div>`).join("") : empty("merge", "No identity decisions awaiting review", "The entity-resolution model resolved every observation with sufficient confidence."));
  }
  if (sub === "models") {
    const d = await api("/ml/models");
    body = pb(d.active.map(x => `<div class="dcard"><div class="dh"><b>${esc(MODEL_TITLE[x.name] || x.name)}</b>${badge(x.version, "neutral")}${badge("active", "ok")}${x.name === "contextual-risk" ? badge("rule-weighted heuristic", "warn") : badge("machine learning", "predicted")}</div>
      <div class="kv" style="margin-bottom:12px"><div>Training data</div><div>${esc(x.data_origin)}</div><div>Trained</div><div>${x.trained_at ? `${esc(ago(x.trained_at))} <span class="mut">(${ts(String(x.trained_at).slice(0, 19))} UTC)</span>` : "–"}</div><div>Inferences / errors</div><div>${x.inferences ?? "–"} / ${x.errors}</div>${x.threshold != null ? `<div>Decision threshold</div><div>${num(x.threshold, 4)}</div>` : ""}</div>
      <div class="lbl"><span>Evaluation &amp; training metrics</span></div>${metricsGrid(x.metrics)}${x.metrics?.caveat ? callout("alert", esc(x.metrics.caveat), "warn") : ""}</div>`).join("") +
      `<div class="mut" style="margin:4px 0 12px">Training vectors collected from this platform: <b class="tx2">${d.training_vectors_collected}</b></div>${ADMIN() ? `<button class="btn" data-act="retrain">${ic("refresh", "sm")}Retrain anomaly model on platform data</button>` : ""}`) +
      `<div class="sect" style="padding:0 16px">Model versions</div>` + table(["Model", "Version", "Trained", "Status", "Data origin", "Key metrics"], (d.history || []).map(h => ({ cells: [esc(MODEL_TITLE[h.name] || h.name), `<span class="mono">${esc(h.version)}</span>`, when(h.trained_at), badge(h.status, h.status === "active" ? "ok" : "neutral"), esc(h.data_origin), `<span class="mut">${esc(Object.entries(h.metrics || {}).filter(([k, v]) => typeof v === "number").slice(0, 4).map(([k, v]) => `${k} ${Number.isInteger(v) ? v : +v.toFixed(3)}`).join(" · "))}</span>`] })), null, { empty: empty("history", "No model runs recorded") });
  }
  if (sub === "catalog") {
    const [d, i] = await Promise.all([api("/vulnerabilities?size=100"), api("/intelligence")]), ks = i.catalog.last_kev_sync;
    body = pb(`<div class="pills" style="margin-bottom:10px"><span class="pill">${i.catalog.vulnerabilities} CVEs</span><span class="pill">${i.catalog.kev} known exploited (KEV)</span><span class="pill">Last KEV sync: ${ks ? esc(typeof ks === "string" ? ks : JSON.stringify(ks)) : "never"}</span></div><div class="hint" style="margin:0 0 ${ADMIN() ? 10 : 0}px">Seed catalog is a snapshot — sync KEV for authoritative data.</div>${ADMIN() ? `<button class="btn" data-act="kev">${ic("refresh", "sm")}Sync CISA KEV</button>` : ""}`) +
      table(["CVE", "CVSS", "KEV", "Exploit", "Affected", "Description"], d.items.map(v => ({ cells: [`<span class="mono primary">${esc(v.cve)}</span>`, num(v.cvss, 1), v.kev ? '<span class="badge kev">KEV</span>' : "", v.exploit_available ? badge("yes", "warn") : "", v.affected_findings, `<div class="wrap" title="${esc(v.description || "")}">${esc((v.description || "").slice(0, 110))}</div>`] })));
  }
  m.innerHTML = ph("Intelligence", "Machine-learning anomaly detection, identity resolution and vulnerability intelligence.") + `<div class="tabs">${tabs.map(t => `<a href="#/intelligence/${t}" class="${t === sub ? "on" : ""}">${t}</a>`).join("")}</div>${panel("", body)}`;
};
// ---- investigations / reports
P.investigations = async (m, id) => {
  if (id) {
    const i = await api("/investigations/" + id); S.ctx = { page: "investigation", investigation_id: +id, asset_id: i.asset_ids[0] };
    const kind = t => t.kind === "anomaly" ? "anomaly" : t.kind === "note" ? "note" : "change";
    m.innerHTML = ph(`#${i.id} ${esc(i.title)} ${badge(human(i.status), i.status === "closed" ? "ok" : "info")}`, "", "", `<a href="#/investigations">Investigations</a> / #${i.id}`) + `<div class="g2"><div>${panel("Scope", pb(`<div class="lbl"><span>Assets</span></div>${i.assets.map(a => `<div style="margin-bottom:6px">${link("assets/" + a.id, a.name)} ${lv(a.risk_level)}</div>`).join("") || "–"}<div class="divider"></div><div class="lbl"><span>Findings</span></div>${i.findings.map(f => `<div style="margin-bottom:6px">${link("findings/" + f.id, f.cve + " @ " + f.asset)}</div>`).join("") || "–"}`))}
      ${panel("Conclusion", pb(`${esc(i.conclusion) || '<span class="mut">No conclusion yet.</span>'} ${i.outcome ? `<div style="margin-top:8px"><span class="badge analyst">validated: ${esc(i.outcome)} by ${esc(i.validated_by)}</span></div>` : ""}`))}</div>
      ${panel("Timeline", pb(i.timeline.length ? `<div class="tl">${i.timeline.slice(-40).map(t => `<div class="ev k-${kind(t)}"><div class="t1">${when(t.ts)}${basis(t.basis)}${esc(t.asset)}</div><div class="t2">${esc(t.text)}</div></div>`).join("")}</div>` : empty("history", "No timeline events yet")), "evidence in chronological order")}</div>
      ${WRITE() ? panel("Add note", pb(`<div class="fbar" style="margin:0"><input id="nt" placeholder="Analyst note" maxlength="2000" style="flex:1;min-width:200px"><button class="btn" data-act="note" data-id="${i.id}">Add note</button></div>`)) : ""}
      ${["administrator", "analyst", "manager"].includes(S.user.role) ? panel("Validate & close", pb(`<div class="fbar" style="margin:0"><select id="vo" aria-label="Outcome"><option>true_positive</option><option>false_positive</option><option>benign</option><option>unknown</option></select><input id="vc" placeholder="Conclusion (at least 3 characters)" maxlength="4000" style="flex:1;min-width:220px"><button class="btn pri" data-act="validate" data-id="${i.id}">${ic("check", "sm")}Validate &amp; close</button></div>`)) : ""}`;
    return;
  }
  const d = await api("/investigations");
  m.innerHTML = ph(`Investigations <span class="count">${d.length}</span>`, "Evidence-grounded investigations. Start one from an asset or finding.") + panel("", table(["#", "Title", "Status", "Assets", "Outcome", "Updated"], d.map(i => ({ id: i.id, cells: [i.id, `<span class="primary">${esc(i.title)}</span>`, badge(human(i.status), i.status === "closed" ? "ok" : "info"), i.asset_ids.length, i.outcome ? badge(human(i.outcome), "analyst") : '<span class="mut">–</span>', when(i.updated_at)] })), r => "investigations/" + r.id, { empty: empty("investigations", "No investigations yet", "Open an asset or finding and choose “Start investigation”.") }));
};
P.reports = async m => {
  const d = await api("/reports");
  m.innerHTML = ph("Reports", "Generate evidence-based reports. Each states its scope, sources and limitations.") + `<div class="reports">${d.map(r => `<div class="rep"><h4>${ic("reports")}${esc(r.title)}</h4><div class="acts">${["html", "csv", "json"].map(f => `<button class="btn sm" data-rep="${esc(r.kind)}:${f}">${ic("download", "sm")}${f.toUpperCase()}</button>`).join("")}</div></div>`).join("") || empty("reports", "No reports available")}</div>`;
};
// ---- administration
const kvTree = (o, d = 0) => `<div class="kv">${Object.entries(o || {}).map(([k, v]) => `<div>${esc(human(k))}</div><div>${v && typeof v === "object" ? (Array.isArray(v) ? esc(JSON.stringify(v)) : kvTree(v, d + 1)) : typeof v === "boolean" ? badge(v ? "yes" : "no", v ? "ok" : "neutral") : esc(v ?? "–")}</div>`).join("")}</div>`;
P.admin = async m => {
  const t = ADMIN() ? (S.tab.admin || "system") : "system"; let body = "";
  if (t === "system") {
    const s = await api("/system/status").catch(e => null);
    body = s ? pb(`<div class="pills" style="margin-bottom:12px">${badge("API " + s.api, s.api === "ok" ? "ok" : "error")}${badge("Database " + s.database + (s.database_engine ? " (" + s.database_engine + ")" : ""), s.database === "ok" ? "ok" : "error")}${badge(`Integrations ${s.integrations?.total ?? "–"} · unhealthy ${s.integrations?.unhealthy ?? "–"}`, s.integrations?.unhealthy ? "warn" : "ok")}</div>${kvTree(s)}${ADMIN() ? '<div class="fbar" style="margin-top:14px"><button class="btn" data-act="sweep">Lifecycle sweep</button></div>' : ""}`) : pb(callout("info", "System status is available to administrators and managers."));
  }
  if (t === "users") { const u = await api("/users"); body = table(["User", "Role", "Active", "Last login"], u.map(x => ({ cells: [`<span class="primary">${esc(x.username)}</span>`, badge(x.role, "neutral"), x.active ? badge("active", "ok") : badge("disabled", "neutral"), x.last_login ? when(x.last_login) : '<span class="mut">never</span>'] }))) + `<div class="sect" style="padding:0 16px">Create user</div>` + pb(`<form class="fbar" id="uf" style="margin:0"><input name="u" placeholder="Username (3–64: letters, digits, _ . @ -)" required minlength="3" maxlength="64" pattern="[A-Za-z0-9_.@\\-]+" aria-label="Username"><input name="p" type="password" placeholder="Password (12+ characters)" required minlength="12" maxlength="256" aria-label="Password"><select name="r" aria-label="Role"><option>readonly</option><option>manager</option><option>analyst</option><option>administrator</option></select><button class="btn pri">${ic("plus", "sm")}Create user</button></form>`); }
  if (t === "audit") { const a = await api("/audit?limit=150"); body = table(["Time", "User", "Action", "Resource", "Detail"], a.map(x => ({ cells: [`<span class="nowrap" title="${ts(x.ts)} UTC">${ts(x.ts)}</span>`, esc(x.user), `<span class="badge neutral">${esc(x.action)}</span>`, `<span class="mono">${esc(x.resource)}</span>`, `<span class="mut mono" title="${esc(JSON.stringify(x.detail))}">${esc(JSON.stringify(x.detail).slice(0, 120))}</span>`] }))); }
  m.innerHTML = ph("Administration", "System health, users and the audit trail.") + `<div class="tabs">${(ADMIN() ? ["system", "users", "audit"] : ["system"]).map(x => `<button data-tab="admin:${x}" class="${x === t ? "on" : ""}">${x}</button>`).join("")}</div>${panel("", body)}`;
  const uf = $("#uf", m); if (uf) uf.onsubmit = async e => { e.preventDefault(); const f = new FormData(uf); try { await api("/users", { method: "POST", body: { username: f.get("u"), password: f.get("p"), role: f.get("r") } }); toast("User created", "ok"); render(); } catch (x) { toast(x.message, "err"); } };
};

// ================================================================ 6. integrations
const sleep = ms => new Promise(r => setTimeout(r, ms));
const TILES = [
  { kind: "tcp_discovery", icon: "target", title: "TCP Connect Discovery", steps: "Configure → Test → Collect", desc: "Agentless connect checks of authorised IP addresses and CIDR ranges. No payloads are sent; banners are read only on a few protocols." },
  { kind: "nmap_xml", icon: "globe", title: "Nmap scan import", steps: "Choose integration → Select XML → Import", desc: "Upload the XML output of an authorised Nmap scan (nmap -oX) to add hosts, open ports and services." },
  { kind: "vuln_scan", icon: "shieldok", title: "Vulnerability scan import", steps: "Choose integration → Select CSV/JSON → Import", desc: "Upload a scanner export (CSV or JSON). Findings are recorded as observed and matched to assets." },
];
const FILE_EXT = { nmap_xml: ["xml"], vuln_scan: ["csv", "json"], csv_hosts: ["csv"], generic_json: ["json"], aws_ec2: ["json"], azure_vm: ["json"], oci_instances: ["json"], k8s_json: ["json"] };
const CAT_ORDER = ["infrastructure", "cloud", "container", "security", "api"];
const stKey = s => !s.enabled ? "off" : (s.status || "never_run");
const stLabel = { ok: "OK", partial: "Partial", error: "Error", running: "Running", queued: "Queued", never_run: "Never run", off: "Disabled" };
const stDot = { ok: "ok", partial: "error", error: "error", running: "running", queued: "running", never_run: "off", off: "off" };
function parseJson(txt) {
  const t = (txt || "").trim(); if (!t) return { ok: true, val: {} };
  try { const v = JSON.parse(t); if (!v || typeof v !== "object" || Array.isArray(v)) return { ok: false, err: "Must be a JSON object, e.g. {\"key\": \"value\"}." }; return { ok: true, val: v }; }
  catch (e) { return { ok: false, err: e.message }; }
}
const cntChips = r => r ? `<div class="counts">${[["Received", r.received], ["Processed", r.processed], ["Duplicates", r.duplicates], ["Rejected", r.rejected], ["Failed", r.failed]].map(([l, v]) => `<span class="cnt"><b>${v ?? 0}</b>${l}</span>`).join("")}</div>` : "";
function fbHtml(fb) {
  if (!fb) return "";
  const icon = { running: '<span class="spin"></span>', ok: ic("ok"), partial: ic("alert"), error: ic("xcircle") }[fb.state];
  return `<div class="fb ${esc(fb.state)}" role="status"><h5>${icon}${esc(fb.title)}</h5>${fb.detail ? `<div class="${fb.state === "error" ? "mono" : ""}" style="white-space:pre-wrap;word-break:break-word">${esc(fb.detail)}</div>` : ""}${cntChips(fb.run)}${fb.run ? `<div class="hint">Run #${fb.run.id} · started ${ts(fb.run.started)} UTC · duration ${dur(fb.run.started, fb.run.finished)}</div>` : ""}</div>`;
}
function runOutcome(r, verb) {
  if (r.status === "error") return { state: "error", title: verb + " failed", detail: r.error || "" };
  if (r.status === "partial") return { state: "partial", title: verb + " completed with failures", detail: r.error || "" };
  if (!r.received) return { state: "partial", title: verb + " completed — no records found", detail: "The run finished without errors but the source returned no usable records." };
  if (!r.processed && (r.duplicates || 0) < r.received) return { state: "partial", title: verb + " completed — nothing was ingested", detail: `The run finished without errors, but none of the ${r.received} received record(s) were ingested (rejected ${r.rejected || 0}, failed ${r.failed || 0}). Check the source data.` };
  return { state: "ok", title: verb + " completed", detail: r.error || "" };
}
function setFb(id, fb) { S.int.fb[id] = fb; const el = $("#fb-" + id); if (el) el.innerHTML = fbHtml(fb); }
function cfgChips(s) {
  const c = s.config || {};
  if (s.kind === "tcp_discovery") return `<div class="pills cfg">${c.authorized === true ? badge("authorised", "ok") : badge("not authorised — scans will be refused", "warn")}<span class="pill">${Array.isArray(c.targets) ? c.targets.length : 0} target${(c.targets || []).length === 1 ? "" : "s"}</span><span class="pill">${Array.isArray(c.ports) ? c.ports.length : "default"} ports</span><span class="pill">timeout ${esc(c.timeout ?? 1.5)}s</span></div>`;
  if (s.kind === "http_json" && c.url) { let h = c.url; try { h = new URL(c.url).host; } catch (e) {} return `<div class="pills cfg"><span class="pill mono">${esc(h)}</span></div>`; }
  return "";
}
function intCard(s, cmap) {
  const k = stKey(s), adm = ADMIN(), sel = S.int.sel === s.id;
  return `<div class="icard ${sel ? "sel" : ""}" ${adm ? `data-int="${s.id}:select"` : ""}><div class="top"><span class="dot ${stDot[k] || "off"}"></span><span class="nm" title="${esc(s.name)}">${esc(s.name)}</span>${badge(stLabel[k] || human(k), k === "ok" ? "ok" : k === "error" ? "error" : k === "running" ? "running" : "neutral")}</div>
    <div class="meta"><span>${esc(s.kind_label)}</span><span>Auth: <b>${esc(s.auth_status)}</b></span><span>Schedule: <b>${s.frequency_minutes ? "every " + s.frequency_minutes + " min" : "manual"}</b></span></div>
    <div class="meta"><span>Last success: <b>${s.last_success ? when(s.last_success) : "never"}</b></span><span>Last attempt: <b>${s.last_attempt ? when(s.last_attempt) : "never"}</b></span></div>${cfgChips(s)}
    ${s.last_error ? `<div class="err" title="${esc(s.last_error)}">${esc(s.last_error.slice(0, 160))}</div>` : ""}
    ${adm ? `<div class="acts"><button class="btn sm" data-int="${s.id}:test">${ic("flask", "sm")}Test</button>${s.schedulable ? `<button class="btn sm" data-int="${s.id}:collect" ${s.enabled ? "" : 'disabled title="Integration is disabled"'}>${ic("play", "sm")}Collect</button>` : ""}${s.accepts_upload ? `<button class="btn sm" data-int="${s.id}:import">${ic("upload", "sm")}Import file</button>` : ""}<button class="btn sm ghost" data-int="${s.id}:runs">${ic("history", "sm")}Run history</button></div>` : ""}</div>`;
}
function runsTable(runs) {
  const okN = runs.filter(r => r.status === "ok").length, bad = runs.filter(r => r.status === "error").length, part = runs.filter(r => r.status === "partial").length;
  return `<div class="pills" style="padding:12px 16px 0"><span class="pill">${runs.length} run${runs.length === 1 ? "" : "s"} shown</span>${okN ? badge(okN + " succeeded", "ok") : ""}${part ? badge(part + " partial", "partial") : ""}${bad ? badge(bad + " failed", "error") : ""}</div>` +
    table(["Started", "Status", "Result"], runs.map(x => ({ cells: [`<span title="${ts(x.started)} UTC">${esc(ago(x.started))}</span><div class="secondary"><span class="nowrap">${ts(x.started)}</span> · ${esc(x.trigger)} · ${dur(x.started, x.finished)}</div>`, runBadge(x.status),
      `<div class="pills"><span class="cnt"><b>${x.received}</b>received</span><span class="cnt"><b>${x.processed}</b>processed</span>${x.duplicates ? `<span class="cnt"><b>${x.duplicates}</b>duplicate</span>` : ""}${x.rejected ? `<span class="cnt"><b>${x.rejected}</b>rejected</span>` : ""}${x.failed ? `<span class="cnt" style="color:#ff8f8b"><b style="color:#ff8f8b">${x.failed}</b>failed</span>` : ""}</div>`], after: x.error ? `<tr class="errrow"><td colspan="3">${esc(x.error)}</td></tr>` : "" })), null, { empty: empty("history", "No runs yet", "Run a collection or import a file to see execution history.") });
}
P.integrations = async m => {
  const [d, c] = await Promise.all([api("/integrations"), api("/connectors")]); S.int.list = d; S.int.conns = c;
  const cmap = Object.fromEntries(c.map(x => [x.kind, x])), adm = ADMIN();
  if (S.int.sel && !d.find(x => x.id === S.int.sel)) S.int.sel = null;
  const sel = S.int.sel && d.find(x => x.id === S.int.sel); let runs = [];
  if (sel && adm) { try { runs = await api(`/integrations/${sel.id}/runs`); } catch (e) { toast(e.message, "err"); } }
  const cnt = k => d.filter(s => stKey(s) === k).length;
  const tiles = adm ? `<div class="tiles">${TILES.filter(t => cmap[t.kind]).map(t => { const have = d.filter(s => s.kind === t.kind), imp = t.kind !== "tcp_discovery";
    return `<div class="tile"><div class="th"><span class="ti">${ic(t.icon, "lg")}</span><div><h4>${esc(t.title)}</h4><div class="steps">${esc(t.steps)}</div></div></div><p>${esc(t.desc)}</p><div class="ta">${imp && have.length ? `<button class="btn pri" data-w="import:${have[0].id}">${ic("upload", "sm")}Import scan file</button>` : `<button class="btn pri" data-w="add:${t.kind}">${ic("plus", "sm")}${imp ? "Set up integration" : "Configure discovery"}</button>`}${have.length && !imp ? `<button class="btn" data-int="${have[0].id}:select">Open “${esc(have[0].name.length > 18 ? have[0].name.slice(0, 17) + "…" : have[0].name)}”</button>` : ""}<span class="mut" style="align-self:center;font-size:12px">${have.length} configured</span></div></div>`; }).join("")}</div>` : "";
  const detail = sel ? `<section class="panel"><div class="ph2"><h3 class="nm">${esc(sel.name)}</h3><span class="hint">${esc(sel.kind_label)}</span></div><div class="pb"><div id="fb-${sel.id}">${fbHtml(S.int.fb[sel.id])}</div>
      <div class="acts" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px"><button class="btn sm" data-int="${sel.id}:test">${ic("flask", "sm")}Test</button>${sel.schedulable ? `<button class="btn sm pri" data-int="${sel.id}:collect" ${sel.enabled ? "" : "disabled"}>${ic("play", "sm")}Collect now</button>` : ""}${sel.accepts_upload ? `<button class="btn sm pri" data-int="${sel.id}:import">${ic("upload", "sm")}Import file</button>` : ""}</div>
      <div class="lbl"><span>Configuration</span><span class="mut" style="font-weight:400">credentials are encrypted and never shown</span></div>${jsonView(sel.config || {}, "cfgj")}</div></section>
      <section class="panel"><div class="ph2"><h3>Run history</h3><span class="hint">latest 50</span></div>${runsTable(runs)}</section>`
    : `<section class="panel"><div class="ph2"><h3>How it works</h3></div><div class="pb"><div class="stepper"><div><span><b>Configure</b><span>Add an integration and set its targets or import options.</span></span></div><div><span><b>Test</b><span>Validate the configuration before anything runs.</span></span></div><div><span><b>Collect or import</b><span>Run discovery now or upload a scan file. Results are ingested, matched to assets and risk-scored.</span></span></div><div><span><b>Review</b><span>Check run counts and any errors in the run history.</span></span></div></div>${adm ? '<div class="hint" style="margin-top:14px">Select an integration to see its configuration and run history.</div>' : '<div class="callout">' + ic("info") + "<div>Running integrations and viewing run history requires an administrator account.</div></div>"}</div></section>`;
  m.innerHTML = ph(`Integrations <span class="count">${d.length}</span>`, "Connect data sources, run discovery and import scan results.", adm ? `<button class="btn" data-w="import:">${ic("upload", "sm")}Import scan file</button><button class="btn pri" data-w="add:">${ic("plus", "sm")}Add integration</button>` : "") + tiles +
    `<div class="strip"><div><b>${d.length}</b><span>Total</span></div><div><b>${cnt("ok")}</b><span>Healthy</span></div><div><b style="${cnt("error") ? "color:#ff8f8b" : ""}">${cnt("error")}</b><span>With errors</span></div><div><b>${cnt("running") + cnt("queued")}</b><span>Running / queued</span></div><div><b>${cnt("never_run") + cnt("off")}</b><span>Never run / disabled</span></div></div>
    <div class="intg"><div>${d.map(s => intCard(s, cmap)).join("") || panel("", empty("integrations", "No integrations configured", adm ? "Add an integration to start collecting data." : ""))}</div><div class="sticky">${detail}</div></div>
    <div class="hint">Credentials are encrypted at rest and never displayed. Cloud/vendor exports are imported as files; HTTP and authorised TCP discovery collectors can run on a schedule.</div>`;
};
async function intAction(id, a, btn) {
  id = +id;
  if (a === "select" || a === "runs") { S.int.sel = id; render(); return; }
  if (a === "test") await busy(btn, async () => { const r = await api(`/integrations/${id}/test`, { method: "POST" }); S.int.sel = id;
    S.int.fb[id] = { kind: "test", state: r.ok ? "ok" : "error", title: r.ok ? "Test passed" : "Test failed", detail: r.detail }; toast((r.ok ? "OK: " : "Failed: ") + r.detail, r.ok ? "ok" : "err"); render(); });
  if (a === "collect") await busy(btn, async () => { const prev = (await api(`/integrations/${id}/runs`))[0]?.id || 0; await api(`/integrations/${id}/collect`, { method: "POST" }); S.int.sel = id;
    S.int.fb[id] = { kind: "collect", state: "running", title: "Collection running", detail: "DEEPSIGHT is collecting from the configured targets. This panel updates when the run finishes." }; toast("Collection started", "info"); render(); watchCollect(id, prev); });
  if (a === "import") openImport(id);
}
async function watchCollect(id, prev) {
  if (S.int.watch === id) return; S.int.watch = id; const t0 = Date.now(); let n = 0;
  try {
    for (;;) {
      await sleep(n++ < 3 ? 1500 : 3000); if (!S.token) return;
      let runs; try { runs = await api(`/integrations/${id}/runs`); } catch (e) { setFb(id, { kind: "collect", state: "error", title: "Lost contact while checking progress", detail: e.message }); break; }
      const r = runs[0];
      if (r && r.id > prev && r.status !== "running") {
        const o = runOutcome(r, "Collection"); setFb(id, { kind: "collect", state: o.state, run: r, detail: o.detail, title: o.title });
        toast(o.state === "ok" ? `Collection completed: ${r.processed} processed` : o.title + (o.state === "error" && r.error ? ": " + r.error : ""), o.state === "ok" ? "ok" : o.state === "partial" ? "warn" : "err"); break; }
      if ((!r || r.id <= prev) && Date.now() - t0 > 30000) { const stt = await api(`/integrations/${id}/status`).catch(() => null);
        if (stt && !["running", "queued"].includes(stt.status)) { setFb(id, { kind: "collect", state: "error", title: "No run was recorded", detail: stt.last_error || "The collection did not start. Check the integration configuration and server logs." }); break; } }
      if (Date.now() - t0 > 15 * 60000) { setFb(id, { kind: "collect", state: "partial", title: "Still running", detail: "The run is taking longer than 15 minutes. Open the run history to follow it." }); break; }
    }
  } finally { S.int.watch = null; if (location.hash.startsWith("#/integrations")) render(); }
}

// ---- Import dialog
function openImport(preId) {
  const list = (S.int.list || []).filter(s => s.accepts_upload), cmap = Object.fromEntries((S.int.conns || []).map(x => [x.kind, x])); let file = null, busyNow = false;
  if (!list.length) { const m = openModal({ title: "Import scan file", body: empty("integrations", "No import-capable integration yet", "Add an integration of type “Nmap scan”, “Vulnerability scan results” or another file-based type first."), footer: `<button class="btn" data-mclose2>Close</button><button class="btn pri" id="go-add">${ic("plus", "sm")}Add integration</button>` });
    m.q("[data-mclose2]").onclick = () => m.close(); m.q("#go-add").onclick = () => { m.close(); openAdd(); }; return; }
  const m = openModal({ title: "Import scan file", size: "wide", persist: true, body: `<div class="fld"><label for="imp-int">Integration</label><select id="imp-int">${list.map(s => `<option value="${s.id}" ${+preId === s.id ? "selected" : ""}>${esc(s.name)} — ${esc(s.kind_label)}${s.enabled ? "" : " (disabled)"}</option>`).join("")}</select><div class="hint" id="imp-desc"></div></div>
    <div class="fld"><label>File</label><div id="imp-drop" class="drop" tabindex="0" role="button" aria-label="Choose a file to import">${ic("upload")}<b>Drop a file here or click to browse</b><span id="imp-accept"></span></div><input type="file" id="imp-file" hidden></div><div id="imp-warn"></div><div id="imp-res"></div>`,
    footer: `<button class="btn" id="imp-cancel">Cancel</button><button class="btn pri" id="imp-go" disabled>${ic("upload", "sm")}Upload &amp; import</button>` });
  const sel = m.q("#imp-int"), fi = m.q("#imp-file"); let go = m.q("#imp-go");
  const cur = () => list.find(s => s.id === +sel.value), exts = () => FILE_EXT[cur().kind] || [];
  const warn = () => { const w = []; if (file) { const ext = file.name.split(".").pop().toLowerCase(), want = exts(); if (want.length && !want.includes(ext)) w.push(`“${file.name}” doesn't look like a ${want.map(x => "." + x).join(" / ")} file, which is what ${cur().kind_label} expects. DEEPSIGHT will still try to parse it.`); if (file.size > 20e6) w.push("This file is larger than 20 MB and may exceed the platform's 20,000,000-character import limit."); if (file.name.length > 200) w.push("The file name is longer than 200 characters, which the platform rejects."); }
    m.q("#imp-warn").innerHTML = w.map(x => `<div class="fwarn">${ic("alert", "sm")} ${esc(x)}</div>`).join(""); };
  const refresh = () => { const s = cur(), c = cmap[s.kind]; m.q("#imp-desc").textContent = c ? c.description : ""; m.q("#imp-accept").textContent = exts().length ? "Expected: " + exts().map(x => "." + x).join(", ") : ""; fi.accept = exts().length ? exts().map(x => "." + x).join(",") : ""; warn(); };
  const showFile = () => { m.q("#imp-drop").outerHTML = `<div id="imp-drop" class="filecard">${ic("file")}<div class="fi"><div class="fn">${esc(file.name)}</div><div class="mut">${bytes(file.size)}</div></div><button class="btn sm" data-change type="button">Change</button></div>`; go.disabled = false; warn(); };
  const pick = f => { if (!f) return; file = f; showFile(); bindChange(); };
  const bindChange = () => { const b = m.q("[data-change]"); if (b) b.onclick = () => { fi.value = ""; fi.click(); }; };
  sel.onchange = () => { refresh(); }; refresh();
  const dz = () => { const d = m.q("#imp-drop"); if (!d || !d.classList.contains("drop")) return; d.onclick = () => fi.click(); d.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fi.click(); } };
    d.ondragover = e => { e.preventDefault(); d.classList.add("over"); }; d.ondragleave = () => d.classList.remove("over"); d.ondrop = e => { e.preventDefault(); d.classList.remove("over"); pick(e.dataTransfer.files[0]); }; }; dz();
  fi.onchange = () => pick(fi.files[0]); m.q("#imp-cancel").onclick = () => m.close();
  const reset = () => { file = null; fi.value = ""; m.q("#imp-res").innerHTML = ""; const ex = m.q("#imp-drop"); ex.outerHTML = `<div id="imp-drop" class="drop" tabindex="0" role="button" aria-label="Choose a file to import">${ic("upload")}<b>Drop a file here or click to browse</b><span id="imp-accept"></span></div>`; dz(); refresh(); sel.disabled = false;
    const f = m.q("footer"); f.innerHTML = `<button class="btn" id="imp-cancel">Cancel</button><button class="btn pri" id="imp-go" disabled>${ic("upload", "sm")}Upload &amp; import</button>`; m.q("#imp-cancel").onclick = () => m.close(); m.q("#imp-go").onclick = run; go = m.q("#imp-go"); };
  async function run() {
    if (!file || busyNow) return; const s = cur(), id = s.id; busyNow = true; sel.disabled = true; m.q("#imp-go").disabled = true;
    m.q("#imp-res").innerHTML = `<div class="fb running"><h5><span class="spin"></span>Processing ${esc(file.name)}…</h5><div>Uploading and parsing the file. DEEPSIGHT ingests it synchronously, so large files can take a while — keep this window open.</div></div>`;
    try {
      const txt = await file.text(); if (txt.length > 20000000) throw new Error("The file exceeds the platform's 20,000,000-character import limit.");
      const r = await api(`/integrations/${id}/import`, { method: "POST", body: { filename: file.name, content: txt } });
      const o = runOutcome(r, "Import"), st = o.state;
      S.int.sel = id; S.int.fb[id] = { kind: "import", state: st, title: o.title, detail: o.detail, run: r };
      m.q("#imp-res").innerHTML = fbHtml(S.int.fb[id]) + (st !== "ok" && st !== "error" && !r.received ? `<div class="fwarn">${ic("alert", "sm")} Check that this is the format ${esc(s.kind_label)} expects.</div>` : "");
      toast(`Import ${r.status}: ${r.received} received, ${r.processed} processed, ${r.failed} failed`, st === "ok" ? "ok" : st === "partial" ? "warn" : "err");
      m.q("footer").innerHTML = `<button class="btn" id="imp-again">Import another file</button><button class="btn pri" id="imp-done">Done</button>`; m.q("#imp-again").onclick = reset; m.q("#imp-done").onclick = () => m.close(); render();
    } catch (e) {
      m.q("#imp-res").innerHTML = fbHtml({ state: "error", title: "Import failed", detail: e.message }); toast("Import failed: " + e.message, "err");
      sel.disabled = false; go.disabled = false;
    } finally { busyNow = false; }
  }
  go.onclick = run; bindChange();
}

// ---- Add-integration dialog (guided TCP form <-> exact existing JSON config)
const parsePorts = txt => { const out = [], bad = []; for (const tok of txt.split(/[\s,;]+/).filter(Boolean)) { const mm = tok.match(/^(\d{1,5})(?:-(\d{1,5}))?$/); if (!mm) { bad.push(tok); continue; } const a = +mm[1], b = mm[2] ? +mm[2] : a; if (a < 1 || b > 65535 || b < a) { bad.push(tok); continue; } for (let p = a; p <= b && out.length < 5000; p++) out.push(p); } return { ports: [...new Set(out)], bad }; };
const parseTargets = txt => txt.split(/[\s,;]+/).filter(Boolean);
function hostEstimate(ts) { let n = 0, unk = []; for (const t of ts) { const mm = t.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/); if (!mm || mm[1].split(".").some(o => +o > 255)) { if (!t.includes(":")) unk.push(t); continue; } if (mm[2] === undefined) n++; else { const p = +mm[2]; if (p > 32) { unk.push(t); continue; } const a = 2 ** (32 - p); n += a > 2 ? a - 2 : a; } } return { n, unk }; }
const parseHostnames = txt => { const o = {}, bad = []; for (const line of txt.split("\n")) { const l = line.trim(); if (!l) continue; const mm = l.match(/^(\S+?)\s*[=\s]\s*(.+)$/); if (!mm) bad.push(l); else o[mm[1]] = mm[2].trim(); } return { o, bad }; };
const IOT_PORTS = [554, 631, 1883, 2323, 8000, 8291, 8554, 8883, 9100];   // convenience preset only; mirrors the IoT ports the connector already scans by default
function openAdd(preKind) {
  const conns = S.int.conns || []; if (!conns.length) return toast("Connector list is unavailable. Reload the page and try again.", "err");
  const cats = CAT_ORDER.filter(c => conns.some(x => x.category === c)).concat([...new Set(conns.map(x => x.category))].filter(c => !CAT_ORDER.includes(c)));
  const m = openModal({ title: "Add integration", size: "wide", persist: true, body: `<form id="addf" novalidate>
    <div class="frow" style="grid-template-columns:1fr 1fr"><div class="fld"><label for="add-name">Name</label><input id="add-name" name="name" required minlength="2" maxlength="128" placeholder="e.g. lab-tcp-discovery" autocomplete="off"></div>
    <div class="fld"><label for="add-kind">Integration type</label><select id="add-kind" name="kind">${cats.map(c => `<optgroup label="${esc(c)}">${conns.filter(x => x.category === c).map(x => `<option value="${esc(x.kind)}" ${x.kind === preKind ? "selected" : ""}>${esc(x.label)}</option>`).join("")}</optgroup>`).join("")}</select></div></div>
    <div class="hint" id="add-kdesc" style="margin:-6px 0 14px"></div><div id="tcpgui"></div>
    <div class="fld"><label for="add-config"><span>Configuration (JSON)</span><span id="add-cstat" style="font-weight:400"></span></label><div class="jsonbar"><button class="btn sm" type="button" id="j-tpl">Insert template</button><button class="btn sm" type="button" id="j-fmt">Format</button></div><textarea id="add-config" name="config" class="code" rows="9" spellcheck="false" autocomplete="off" placeholder='{ }'></textarea><div class="ferr" id="add-cerr"></div></div>
    <details class="adv"><summary>Secrets (optional — stored encrypted, never shown again)</summary><div><textarea id="add-secrets" name="secrets" class="code" rows="3" spellcheck="false" autocomplete="off" placeholder='{"headers": {"Authorization": "Bearer …"}}'></textarea><div class="ferr" id="add-serr"></div></div></details>
    <div class="fld" style="max-width:260px"><label for="add-freq">Collection schedule (minutes)</label><input id="add-freq" name="freq" type="number" min="0" max="10080" value="0"><div class="hint" id="add-fhint">0 = manual only.</div></div><div class="ferr" id="add-err" role="alert"></div></form>`,
    footer: `<button class="btn" id="add-cancel" type="button">Cancel</button><button class="btn pri" id="add-go" type="button">${ic("plus", "sm")}Add integration</button>` });
  const kind = m.q("#add-kind"), cfg = m.q("#add-config"), cur = () => conns.find(x => x.kind === kind.value); let dirty = false;
  const tplText = () => { const t = cur().config_template || {}; return Object.keys(t).length ? fmtJson(t) : "{}"; };
  const check = () => { const r = parseJson(cfg.value); m.q("#add-cstat").innerHTML = r.ok ? '<span class="fok">✓ valid JSON object</span>' : ""; m.q("#add-cerr").textContent = r.ok ? "" : "Invalid JSON: " + r.err; return r; };
  // guided TCP discovery fields
  const gui = () => `<div class="panel" style="background:var(--panel2);margin-bottom:14px"><div class="ph2"><h3>TCP discovery settings</h3><span class="hint">edits the JSON below</span></div><div class="pb">
    <label class="chk" style="margin-bottom:14px"><input type="checkbox" id="tg-auth"><span>I am authorised to scan these targets<div class="hint" style="font-weight:400">Required. DEEPSIGHT refuses to scan until this is confirmed (<span class="mono">authorized: true</span>).</div></span></label>
    <div class="fld"><label for="tg-targets"><span>Targets</span><span class="mut" style="font-weight:400">IP addresses or CIDR ranges, one per line</span></label><textarea id="tg-targets" class="code" rows="3" placeholder="10.0.0.5&#10;10.0.0.0/28"></textarea><div class="hint" id="tg-est"></div></div>
    <div class="fld"><label for="tg-ports"><span>Ports</span><span class="mut" style="font-weight:400">comma-separated · ranges like 8000-8010</span></label><input id="tg-ports" class="mono" placeholder="22, 80, 443, 8000-8010"><div class="jsonbar" style="margin:6px 0 0"><button class="btn sm" type="button" data-pp="tpl">Connector defaults</button><button class="btn sm" type="button" data-pp="iot">IoT ports</button><button class="btn sm ghost" type="button" data-pp="clear">Clear</button></div><div class="hint" id="tg-pmsg"></div></div>
    <div class="frow"><div class="fld"><label for="tg-timeout">Timeout (seconds)</label><input id="tg-timeout" type="number" min="0.1" step="0.1"></div><div class="fld"><label for="tg-max">Max hosts (≤ 4096)</label><input id="tg-max" type="number" min="1" max="4096"></div></div>
    <label class="chk"><input type="checkbox" id="tg-rdns"><span>Reverse DNS lookup</span></label>
    <details class="adv" style="margin:12px 0 0"><summary>Advanced: static hostnames and asset type</summary><div><div class="fld"><label for="tg-host"><span>Hostnames</span><span class="mut" style="font-weight:400">one “IP name” per line (no DNS needed)</span></label><textarea id="tg-host" class="code" rows="3" placeholder="172.28.50.10 lab-telnet-device"></textarea><div class="ferr" id="tg-hmsg"></div></div><div class="fld" style="margin:0"><label for="tg-type">Asset type override</label><select id="tg-type"><option value="">(none — detect automatically)</option>${ATYPES.map(t => `<option value="${t}">${esc(human(t))}</option>`).join("")}</select></div></div></details></div></div>`;
  const G = id => m.q("#" + id);
  const guiToJson = () => { if (!G("tg-auth")) return; const p = parseJson(cfg.value), o = p.ok ? p.val : (cur().config_template || {});
    o.authorized = G("tg-auth").checked; o.targets = parseTargets(G("tg-targets").value); const pp = parsePorts(G("tg-ports").value);
    G("tg-pmsg").innerHTML = pp.bad.length ? `<span class="ferr">Invalid port${pp.bad.length > 1 ? "s" : ""}: ${esc(pp.bad.join(", "))}</span>` : pp.ports.length > 200 ? `<span class="fwarn">${pp.ports.length} ports listed — the platform scans at most the first 200.</span>` : `${pp.ports.length} port${pp.ports.length === 1 ? "" : "s"}`;
    if (!pp.bad.length) o.ports = pp.ports; if (G("tg-timeout").value !== "") o.timeout = +G("tg-timeout").value; if (G("tg-max").value !== "") o.max_hosts = parseInt(G("tg-max").value, 10); o.reverse_dns = G("tg-rdns").checked;
    const hn = parseHostnames(G("tg-host").value); G("tg-hmsg").textContent = hn.bad.length ? "Couldn't read: " + hn.bad.join("; ") : ""; if (!hn.bad.length) o.hostnames = hn.o; o.asset_type = G("tg-type").value;
    cfg.value = fmtJson(o); dirty = true; est(); check(); };
  const est = () => { const tg = parseTargets(G("tg-targets").value), e = hostEstimate(tg), mx = parseInt(G("tg-max").value, 10) || 256, pc = parsePorts(G("tg-ports").value).ports.length;
    G("tg-est").innerHTML = tg.length ? `≈ <b class="tx2">${e.n}</b> host${e.n === 1 ? "" : "s"} × ${pc} ports ≈ ${e.n * pc} connection attempts${e.n > mx ? ` <span class="ferr">· exceeds max hosts (${mx}) — the platform will refuse this scan</span>` : ""}${e.unk.length ? ` <span class="fwarn">· not a valid IP/CIDR: ${esc(e.unk.join(", "))}</span>` : ""}` : "Add at least one target."; };
  const jsonToGui = () => { if (!G("tg-auth")) return; const r = parseJson(cfg.value); if (!r.ok) return; const o = r.val;
    G("tg-auth").checked = o.authorized === true; G("tg-targets").value = Array.isArray(o.targets) ? o.targets.join("\n") : ""; G("tg-ports").value = Array.isArray(o.ports) ? o.ports.join(", ") : "";
    G("tg-timeout").value = o.timeout ?? ""; G("tg-max").value = o.max_hosts ?? ""; G("tg-rdns").checked = !!o.reverse_dns; G("tg-host").value = o.hostnames && typeof o.hostnames === "object" ? Object.entries(o.hostnames).map(([k, v]) => `${k} ${v}`).join("\n") : ""; G("tg-type").value = typeof o.asset_type === "string" ? o.asset_type : ""; est();
    const pp = parsePorts(G("tg-ports").value); G("tg-pmsg").textContent = pp.ports.length + " ports"; };
  const onKind = () => { const c = cur(); m.q("#add-kdesc").textContent = c.description || ""; const sch = c.schedulable, fr = m.q("#add-freq");
    fr.disabled = !sch; if (!sch) fr.value = 0; m.q("#add-fhint").textContent = sch ? "0 = manual only. Runs automatically every N minutes (max 10080)." : "This connector is import-only; files are uploaded manually, so no schedule applies.";
    m.q("#tcpgui").innerHTML = c.kind === "tcp_discovery" ? gui() : ""; if (!dirty || !cfg.value.trim()) { cfg.value = tplText(); dirty = false; }
    if (c.kind === "tcp_discovery") { jsonToGui(); $$("#tcpgui input,#tcpgui textarea,#tcpgui select", m.el).forEach(el => el.addEventListener(el.type === "checkbox" || el.tagName === "SELECT" ? "change" : "input", guiToJson));
      $$("[data-pp]", m.el).forEach(b => b.onclick = () => { const t = b.dataset.pp; G("tg-ports").value = t === "tpl" ? (cur().config_template.ports || []).join(", ") : t === "iot" ? IOT_PORTS.join(", ") : ""; guiToJson(); }); }
    check(); };
  kind.onchange = onKind; cfg.addEventListener("input", () => { dirty = true; const r = check(); if (r.ok) jsonToGui(); });
  m.q("#j-tpl").onclick = () => { cfg.value = tplText(); dirty = false; check(); jsonToGui(); }; m.q("#j-fmt").onclick = () => { const r = check(); if (r.ok) cfg.value = Object.keys(r.val).length ? fmtJson(r.val) : "{}"; };
  m.q("#add-cancel").onclick = () => m.close(); onKind();
  const submit = async () => { const err = m.q("#add-err"); err.textContent = ""; const name = m.q("#add-name").value.trim();
    if (name.length < 2 || name.length > 128) { err.textContent = "Name must be 2–128 characters."; m.q("#add-name").focus(); return; }
    const c = check(); if (!c.ok) { err.textContent = "Fix the configuration JSON before saving."; return; }
    const sec = parseJson(m.q("#add-secrets").value); m.q("#add-serr").textContent = sec.ok ? "" : "Invalid secrets JSON: " + sec.err; if (!sec.ok) { err.textContent = "Fix the secrets JSON before saving."; return; }
    const fq = +m.q("#add-freq").value || 0; if (fq < 0 || fq > 10080) { err.textContent = "Schedule must be between 0 and 10080 minutes."; return; }
    const btn = m.q("#add-go"); btn.disabled = true; btn.innerHTML = '<span class="spin"></span>Adding…';
    try { const r = await api("/integrations", { method: "POST", body: { name, kind: kind.value, config: c.val, secrets: sec.val, frequency_minutes: fq } }); toast(`Integration “${name}” added`, "ok"); S.int.sel = r.id; m.close(); render(); }
    catch (x) { err.textContent = x.message; btn.disabled = false; btn.innerHTML = `${ic("plus", "sm")}Add integration`; } };
  m.q("#add-go").onclick = submit; m.q("#addf").onsubmit = e => { e.preventDefault(); submit(); };
}

// ================================================================ 7. events + boot
const CLICKABLE = "[data-act],[data-go],[data-tab],[data-q],[data-an],[data-id-act],[data-rep],[data-int],[data-w],[data-sort],[data-copy]";
document.addEventListener("click", async e => {
  const t = e.target.closest(CLICKABLE); if (!t) return;
  const d = t.dataset, inner = e.target.closest("a[href],button,input,select,textarea,label");
  if (d.go && inner && inner !== t) return;                       // links/buttons inside a clickable row keep their own behaviour
  const done = m => { toast(m, "ok"); render(); };
  try {
    if (d.go) { location.hash = "#/" + d.go; return; }
    if (d.sort !== undefined) { const id = d.tb, i = +d.sort, s = S.sort[id]; S.sort[id] = s && s.i === i ? { i, dir: -s.dir } : { i, dir: 1 }; $("#tb-" + id).innerHTML = stableInner(id); $("#tb-" + id + " [data-sort=\"" + i + "\"]")?.focus(); return; }
    if (d.copy !== undefined) { const el = d.copy ? $("#" + d.copy) : t.parentElement.querySelector("pre"); if (el) copyText(el.textContent); return; }
    if (d.tab) { const [k, v] = d.tab.split(":"); S.tab[k] = v; await render(); $("[role=tab][aria-selected=true]")?.focus(); return; }
    if (d.q) { ask(d.q); return; }
    if (d.w !== undefined) { const [a, v] = d.w.split(":"); if (a === "add") openAdd(v || undefined); if (a === "import") openImport(v || undefined); return; }
    if (d.int) { const [id, a] = d.int.split(":"); await intAction(id, a, t.tagName === "BUTTON" ? t : null); return; }
    if (d.act === "ai") { e.preventDefault(); S.ai = !S.ai; render(); return; }
    if (d.act === "menu") { const sh = $("#shell"); sh?.classList.toggle("nav-open"); syncNavigation(); if (sh?.classList.contains("nav-open")) $(".side-close").focus(); else $(".mtop [data-act=menu]").focus(); return; }
    if (d.act === "logout") { e.preventDefault(); logout(); return; }
    if (d.act === "retry") { render(); return; }
    if (d.act === "pw") { const i = $("#lp"); i.type = i.type === "password" ? "text" : "password"; t.innerHTML = ic(i.type === "password" ? "eye" : "eyeoff"); t.setAttribute("aria-label", i.type === "password" ? "Show password" : "Hide password"); return; }
    if (d.an) { const [id, st] = d.an.split(":"); await busy(t, async () => { await api("/anomalies/" + id, { method: "PATCH", body: { status: st } }); done("Anomaly updated: " + human(st)); }); return; }
    if (d.idAct) { const [id, a] = d.idAct.split(":");
      if (a === "confirm" && !await confirmDialog({ title: "Merge these identities?", message: "The observation's asset will be merged into the candidate asset. A snapshot is kept, so you can revert this decision later.", confirm: "Merge assets" })) return;
      if (a === "revert" && !await confirmDialog({ title: "Revert this identity decision?", message: "The merge will be undone and the assets restored from the saved snapshot.", confirm: "Revert decision", danger: true })) return;
      await busy(t, async () => { await api(`/identity/decisions/${id}/${a}`, { method: "POST", body: {} }); done("Identity decision: " + a); }); return; }
    if (d.rep) { const [k, f] = d.rep.split(":"); await busy(t, async () => { const r = await api(`/reports/${k}?format=${f}`, { raw: true }); download(await r.blob(), `deepsight-${k}.${f}`); toast(`Report downloaded (${f.toUpperCase()})`, "ok"); }); return; }
    if (d.act === "triage") return void await busy(t, async () => { await api("/findings/" + d.id, { method: "PATCH", body: { state: $("#tri").value, note: $("#trn").value || null } }); done("Triage saved"); });
    if (d.act === "inv-finding") return void await busy(t, async () => { const i = await api("/investigations", { method: "POST", body: { title: "Investigate finding " + d.id, finding_ids: [+d.id] } }); location.hash = "#/investigations/" + i.id; });
    if (d.act === "inv-asset") return void await busy(t, async () => { const i = await api("/investigations", { method: "POST", body: { title: "Investigate asset " + d.id, asset_ids: [+d.id] } }); location.hash = "#/investigations/" + i.id; });
    if (d.act === "note") { const v = $("#nt").value.trim(); if (!v) return toast("Enter a note first.", "warn"); return void await busy(t, async () => { await api(`/investigations/${d.id}/notes`, { method: "POST", body: { text: $("#nt").value } }); done("Note added"); }); }
    if (d.act === "validate") { if ($("#vc").value.trim().length < 3) return toast("Add a conclusion of at least 3 characters.", "warn");
      return void await busy(t, async () => { await api(`/investigations/${d.id}/validate`, { method: "POST", body: { outcome: $("#vo").value, conclusion: $("#vc").value } }); done("Investigation validated and closed"); }); }
    if (d.act === "retrain") { if (!await confirmDialog({ title: "Retrain the anomaly model?", message: "The anomaly model will be retrained on data collected by this platform. This replaces the active model version.", confirm: "Retrain" })) return;
      return void await busy(t, async () => { const r = await api("/ml/retrain/anomaly", { method: "POST" }); toast("Retrained: " + JSON.stringify(r).slice(0, 120), "ok"); render(); }); }
    if (d.act === "kev") return void await busy(t, async () => { try { const r = await api("/intelligence/kev-sync", { method: "POST" }); toast("KEV synced " + JSON.stringify(r), "ok"); } catch (x) { toast(x.message, "err"); } render(); });
    if (d.act === "sweep") return void await busy(t, async () => { const r = await api("/system/lifecycle-sweep", { method: "POST" }); toast("Lifecycle sweep: " + JSON.stringify(r), "ok"); });
  } catch (x) { toast(x.message, "err"); }
});
document.addEventListener("keydown", e => {
  const t = e.target;
  if (e.key === "Escape" && !modalClosers.size && $("#shell.nav-open")) { $("#shell").classList.remove("nav-open"); syncNavigation(); $(".mtop [data-act=menu]").focus(); }
  if (t.matches("[data-sort],[data-go]") && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); t.click(); }
  if (t.matches("[role=tab]") && ["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) {
    e.preventDefault(); const tabs = $$("[role=tab]", t.parentElement), i = tabs.indexOf(t);
    const next = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].click();
  }
});
document.addEventListener("change", async e => {
  const t = e.target;
  try { if (t.dataset.crit) { await api("/assets/" + t.dataset.crit, { method: "PATCH", body: { criticality: +t.value } }); toast("Criticality updated", "ok"); render(); } }
  catch (x) { toast(x.message, "err"); render(); }
});
document.addEventListener("input", e => { const t = e.target; if (t.dataset && t.dataset.tbq) { S.q[t.dataset.tbq] = t.value; const el = $("#tb-" + t.dataset.tbq); if (el) el.innerHTML = stableInner(t.dataset.tbq); } });
window.addEventListener("hashchange", render);
window.addEventListener("resize", syncNavigation);
async function boot() {
  if (!S.token) return render();
  $("#app").innerHTML = `<div class="page"><div class="loadmsg" role="status"><span class="spin"></span>Restoring your session…</div></div>`;
  S.restoring = true;
  try { S.user = await api("/auth/me"); try { sessionStorage.setItem("u", JSON.stringify(S.user)); } catch (e) {} }
  catch (e) { S.restoring = false; logout(); toast(e.message, "err"); return; }
  S.restoring = false; render();
}
document.addEventListener("DOMContentLoaded", boot, { once: true });

function freshnessView(f) {
  if (!f) return "Not recently assessed";
  return `<p>${badge(human(f.assessment_state), f.assessment_state === "not_recently_assessed" ? "warn" : "info")} · assessment threshold ${num(f.assessment_age_hours, 0)} hours</p><p>Last successful observation: ${f.last_successful_observation ? ts(f.last_successful_observation) : "Not collected yet"} · Last successful assessment: ${f.last_successful_assessment ? ts(f.last_successful_assessment) : "No complete successful assessment yet"}</p><p>Sources: ${f.sources_seen.map(s => `${esc(s.name)} (${s.recent ? "recent" : "stale"})`).join(", ") || "none"}</p><p>Expected sources missing: ${f.expected_sources_missing.map(s => esc(s.name)).join(", ") || "none configured or missing"}</p>${f.conflicting_evidence.length ? jsonView(f.conflicting_evidence) : "<p>No conflicting evidence among recent source records.</p>"}<div class="hint">${esc(f.limitation)}</div>`;
}

P.queue = async m => {
  const p=qs(), page=pageNumber(p), query=new URLSearchParams(p); query.delete("page");query.set("offset",(page-1)*50);query.set("limit",50);
  const [d,saved]=await Promise.all([api("/work-queue?"+query),api("/saved-filters")]);
  m.innerHTML=ph("Prioritized work queue",d.sort)+panel("Filters",pb(`<form id="queue-filter" class="fbar">${["q","owner","state"].map(k=>`<label>${human(k)}<input name="${k}" value="${esc(p.get(k)||"")}"></label>`).join("")}<button class="btn pri">Apply</button></form><form id="save-filter" class="fbar"><input name="name" placeholder="Save current filters as…" required maxlength="60"><button class="btn">Save filter</button></form><div class="chips">${Object.entries(saved).map(([name,f])=>`<a class="chip" href="#/queue?${esc(new URLSearchParams(f).toString())}">${esc(name)}</a>`).join("")}</div>`))+
    (WRITE()?panel("Bulk triage",pb(`<form id="bulk-form" class="fbar"><label>Owner<input name="owner" required></label><label>Status<select name="state"><option>in_progress</option><option>pending_verification</option><option>new</option></select></label><button class="btn pri">Apply to selected findings</button></form>`)):"")+
    panel(`${d.total} findings`,table(["Select","Finding","Asset","Risk","Why this needs attention"],d.items.map(f=>({cells:[`<input type="checkbox" data-bulk="${f.id}" aria-label="Select finding ${f.id}">`,link("findings/"+f.id,f.cve),link("assets/"+f.asset_id,f.asset),scoreCell(f.contextual_score,f.contextual_level),`<div class="wrap">${f.why_attention.map(esc).join("<br>")}<div class="hint">${esc(f.basis)} · confidence ${num(f.confidence)}</div></div>`]}))))+pageLinks("queue",p,d.total,page,50)+callout("info",d.limitation);
  $("#queue-filter",m).onsubmit=e=>{e.preventDefault();location.hash="#/queue?"+new URLSearchParams(new FormData(e.target));};
  $("#save-filter",m).onsubmit=async e=>{e.preventDefault();try{await api("/saved-filters",{method:"PUT",body:{name:new FormData(e.target).get("name"),filters:Object.fromEntries([...p].filter(([k])=>["q","owner","state"].includes(k)))}});render();}catch(e){toast(e.message,"warn");}};
  const bf=$("#bulk-form",m); if(bf) bf.onsubmit=async e=>{e.preventDefault();try{await api("/bulk-triage",{method:"POST",body:{finding_ids:$$('[data-bulk]:checked',m).map(x=>+x.dataset.bulk),workflow:Object.fromEntries(new FormData(bf))}});toast("Bulk triage saved","ok");render();}catch(e){toast(e.message,"warn");}};
};
P.search = async m => {
  const q=qs().get("q")||"", d=q?await api("/search?q="+encodeURIComponent(q)):{assets:[],findings:[],investigations:[]};
  m.innerHTML=ph("Global search","Search assets, findings and investigations")+`<form id="global-search" class="fbar"><input name="q" value="${esc(q)}" aria-label="Global search" required><button class="btn pri">Search</button></form>`+panel("Assets",pb(d.assets.map(a=>`<p>${link("assets/"+a.id,a.name)}</p>`).join("")||"No matches"))+panel("Findings",findTable(d.findings,"search-findings"))+panel("Investigations",pb(d.investigations.map(i=>`<p>${link("investigations/"+i.id,i.title)}</p>`).join("")||"No matches"));
  $("#global-search",m).onsubmit=e=>{e.preventDefault();location.hash="#/search?"+new URLSearchParams(new FormData(e.target));};
};
