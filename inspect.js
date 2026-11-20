/*!
 * Inspector Pro v5.0 — Gelişmiş Ağ ve Sayfa Denetleyicisi (Eklenti + Yer İmi Çekirdeği)
 * fetch · XHR · WebSocket · sendBeacon · EventSource · console yakalama
 * Eşzamanlı Request / Response / WebSocket Müdahale (Intercept), Repeater, Intruder,
 * Decoder, Karşılaştır, Match & Replace, Ek Script Çalıştırıcı, Sayfa Araçları, HAR/JSON/CSV.
 */
(() => {
'use strict';
const W = window, D = document;
if (W.__inspectorPro) { try { W.__inspectorPro.show(); } catch (e) {} return; }

const EXT = !!W.__IP_EXT, VER = '5.0', CHANNEL = 'inspector-pro-live-v5';

const nativeFetch = W.fetch ? W.fetch.bind(W) : null;
const XHR = W.XMLHttpRequest;
const xhrOpen = XHR.prototype.open, xhrSend = XHR.prototype.send,
      xhrHeader = XHR.prototype.setRequestHeader, xhrAbort = XHR.prototype.abort;
const NativeWS = W.WebSocket;
const NativeES = W.EventSource;
const nativeBeacon = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;
const nativeConsole = {};
['log', 'info', 'warn', 'error', 'debug'].forEach(k => { nativeConsole[k] = console[k].bind(console); });

const LS = {
  get(k, d) { try { const v = W.localStorage.getItem('ip5:' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { W.localStorage.setItem('ip5:' + k, JSON.stringify(v)); } catch (e) {} }
};

let TTP = null;
try { if (W.trustedTypes && W.trustedTypes.createPolicy) TTP = W.trustedTypes.createPolicy('inspector-pro-v5', { createHTML: x => x }); } catch (e) { try { TTP = W.trustedTypes.defaultPolicy || null; } catch (e2) {} }
const H = x => (TTP && TTP.createHTML ? TTP.createHTML(x) : x);

const DEFAULT_SET = {
  mask: true, showBearer: true, bodies: true, max: 800, theme: 'auto', font: 13, outside: false,
  icTimeout: 0, pretty: true, persist: true, startOpen: false,
  panelW: 680, panelH: 720, panelSizePreset: 'standard'
};

const DEFAULT_IC_CFG = {
  reqOn: false,
  resOn: false,
  wsOutOn: false,
  wsInOn: false,
  chainRespAfterReq: true,
  types: { fetch: true, xhr: true, ws: true },
  methods: { GET: true, POST: true, PUT: true, PATCH: true, DELETE: true, OPTIONS: true, HEAD: true },
  filter: '',
  stepMode: true,
  showSettings: true
};

const S = {
  on: true, open: false, full: false, tab: 'history', view: 'list', showF: false,
  requests: [], byId: new Map(), seq: 0, selected: null,
  f: { q: '', method: '', status: '', type: '', star: false, regex: false, inBody: false, host: '', onlyBearer: false },
  set: Object.assign({}, DEFAULT_SET, LS.get('set', {})),
  rules: LS.get('rules', []),
  scripts: LS.get('scripts', { before: '', after: '', custom: '// Sayfa baglaminda anlik JS calistir\nconsole.log("Aktif URL:", location.href);\nreturn { title: document.title, cookies: document.cookie };' }),
  scriptLogs: [],
  /* Birlesik Mudahale Kuyrugu ve Ayarlari */
  icCfg: Object.assign({}, DEFAULT_IC_CFG, LS.get('icCfg', {})),
  icQueue: [],
  icSel: null,
  icView: 'list',
  /* Diger araclar */
  rp: { tabs: [], cur: null },
  in: Object.assign({ method: 'GET', url: '', headers: '', body: '', payloads: '', type: 'sniper', delay: 0, conc: 1, running: false, results: [], sel: null, sort: 'n' }, LS.get('intr', {})),
  cmp: { a: '', b: '', la: '', lb: '', mode: 'line' },
  dec: { inp: '', out: '', op: 'Akilli coz' },
  pg: 'cookies', cons: [], picked: null,
  tabMode: false, channel: null, dashboard: null, disabledSite: false
};

const sensitive = /cookie|secret|password|passwd|api[-_]?key|x-csrf|session/i;
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const safe = v => { try { return typeof v === 'string' ? v : (JSON.stringify(v, null, 2) || String(v)); } catch (e) { return String(v); } };
const limit = (v, n) => String(v == null ? '' : v).slice(0, n || 200000);
const abs = u => { try { return new URL(String(u), D.baseURI).href; } catch (e) { return String(u); } };
const hostOf = u => { try { return new URL(u).host; } catch (e) { return ''; } };
const pathOf = u => { try { const x = new URL(u); return x.pathname + x.search; } catch (e) { return String(u); } };
const fmtB = n => { n = Number(n) || 0; return n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB'; };
const isText = ct => !ct || /text|json|xml|javascript|html|x-www-form|svg|csv|graphql|yaml|urlencoded/i.test(ct);
const isBodyless = m => /^(GET|HEAD)$/i.test(m);
const clone = o => JSON.parse(JSON.stringify(o));

/* ---------- SAF SVG IKON SISTEMI (EMOJI YOK) ---------- */
function svgSym(name) {
  const map = {
    pause: '<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><rect x="3" y="2.5" width="3.5" height="11" rx="0.8"/><rect x="9.5" y="2.5" width="3.5" height="11" rx="0.8"/></svg>',
    play: '<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><polygon points="4,2.5 13.5,8 4,13.5"/></svg>',
    expand: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M10 2.5h3.5V6M6 13.5H2.5V10M13.5 2.5L9.5 6.5M2.5 13.5l4-4"/></svg>',
    shrink: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M13 6H9.5V2.5M3 10h3.5v3.5M13.5 2.5l-4 4M2.5 13.5l4-4"/></svg>',
    close: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3.5 3.5l9 9M12.5 3.5l-9 9"/></svg>',
    back: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10.5 3L5.5 8l5 5"/></svg>',
    star: '<svg viewBox="0 0 16 16" width="13" height="13" fill="currentColor"><polygon points="8,1.8 9.9,5.8 14.3,6.4 11.1,9.5 11.9,13.9 8,11.8 4.1,13.9 4.9,9.5 1.7,6.4 6.1,5.8"/></svg>',
    plus: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M8 3v10M3 8h10"/></svg>',
    down: '<svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M8 3v10M4 9l4 4 4-4"/></svg>',
    up: '<svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M8 13V3M4 7l4-4 4 4"/></svg>',
    arrow: '<svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 8h10M9 4l4 4-4 4"/></svg>',
    sliders: '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 4h12M2 8h12M2 12h12"/><circle cx="5" cy="4" r="1.5" fill="currentColor"/><circle cx="11" cy="8" r="1.5" fill="currentColor"/><circle cx="7" cy="12" r="1.5" fill="currentColor"/></svg>',
    shield: '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M8 2l5 2v4c0 3.3-2.1 5.5-5 6.5-2.9-1-5-3.2-5-6.5V4l5-2z"/></svg>',
    code: '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M5.5 4.5L2 8l3.5 3.5M10.5 4.5L14 8l-3.5 3.5M9 3l-2 10"/></svg>',
    key: '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="5.5" cy="8" r="3"/><path d="M8.5 8H14M12 8v2.5M14 8v2"/></svg>',
    check: '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 8.5l3.5 3.5L13 4.5"/></svg>',
    trash: '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2.5 4.5h11M6 4.5V3h4v1.5M4.5 4.5l.7 8.5h5.6l.7-8.5"/></svg>',
    copy: '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5" y="5" width="8" height="8" rx="1.2"/><path d="M3 11V3.5A1.5 1.5 0 014.5 2H11"/></svg>'
  };
  return `<span class="sym" aria-hidden="true">${map[name] || ''}</span>`;
}

function hdrObj(h) {
  const out = {};
  try {
    const en = (typeof Headers !== 'undefined' && h instanceof Headers) ? [...h.entries()] : Object.entries(h || {});
    en.forEach(([k, v]) => { out[k] = String(v); });
  } catch (e) {}
  return out;
}

/* Bearer token varsa ASLA Redacted yazmaz; her zaman acik gosterir */
function isBearerVal(k, v) {
  return /^bearer\s+/i.test(String(v || '').trim()) || (/authorization/i.test(k) && /bearer/i.test(String(v || '')));
}
function extractBearerTokens(r) {
  const tokens = [];
  const checkMap = (obj, loc) => {
    Object.entries(obj || {}).forEach(([k, v]) => {
      const m = String(v || '').match(/Bearer\s+([A-Za-z0-9\-._~+/]+=*)/i);
      if (m) tokens.push({ loc: loc + ' (' + k + ')', full: m[0], token: m[1] });
    });
  };
  checkMap(r.requestHeaders, 'Istek Header');
  checkMap(r.responseHeaders, 'Yanit Header');
  const bodyHay = (r.requestBody || '') + '\n' + (r.responseBody || '');
  let bm;
  const bre = /["']?(?:access_token|id_token|refresh_token|token|bearer)["']?\s*[:=]\s*["']?(Bearer\s+)?([A-Za-z0-9\-._~+/]{16,}=*)["']?/gi;
  while ((bm = bre.exec(bodyHay))) {
    tokens.push({ loc: 'Govde', full: (bm[1] || 'Bearer ') + bm[2], token: bm[2] });
  }
  const seen = new Set();
  return tokens.filter(t => { if (seen.has(t.token)) return false; seen.add(t.token); return true; });
}
const shown = o => {
  const r = {};
  Object.keys(o || {}).forEach(k => {
    const val = o[k];
    if (isBearerVal(k, val) && S.set.showBearer !== false) {
      r[k] = val;
    } else if (S.set.mask && sensitive.test(k)) {
      r[k] = '[REDACTED]';
    } else {
      r[k] = val;
    }
  });
  return r;
};
const hdrText = o => Object.entries(o || {}).map(([k, v]) => k + ': ' + v).join('\n');
function parseHdr(raw) {
  const out = {};
  String(raw || '').split(/\r?\n/).forEach(l => { const i = l.indexOf(':'); if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
  return out;
}
function describeBody(b) {
  try {
    if (b == null) return '';
    if (typeof b === 'string') return b;
    if (b instanceof URLSearchParams) return b.toString();
    if (typeof FormData !== 'undefined' && b instanceof FormData) return [...b.entries()].map(([k, v]) => k + '=' + (typeof v === 'string' ? v : '[File ' + v.name + ' ' + v.size + 'B]')).join('&');
    if (typeof Blob !== 'undefined' && b instanceof Blob) return '[Blob ' + (b.type || '?') + ' ' + b.size + 'B]';
    if (b instanceof ArrayBuffer) return '[ArrayBuffer ' + b.byteLength + 'B]';
    if (ArrayBuffer.isView(b)) return '[TypedArray ' + b.byteLength + 'B]';
    return String(b);
  } catch (e) { return ''; }
}
const prettyJSON = t => { try { return JSON.stringify(JSON.parse(t), null, 2); } catch (e) { return t; } };

/* ---------- KAYITLAR VE SENKRONIZASYON ---------- */
let rt = 0;
function refresh() { if (rt) return; rt = setTimeout(() => { rt = 0; liveUpdate(); }, 90); }
function addRecord(r) {
  r.id = r.id || uid(); r.n = ++S.seq; r.time = r.time || Date.now();
  if (r.status == null) r.status = 'pending';
  r.requestHeaders = r.requestHeaders || {}; r.responseHeaders = r.responseHeaders || {};
  r.requestBody = r.requestBody == null ? '' : r.requestBody; r.responseBody = r.responseBody == null ? '' : r.responseBody;
  r._v = 0;
  S.requests.unshift(r); S.byId.set(r.id, r);
  while (S.requests.length > S.set.max) { const x = S.requests.pop(); S.byId.delete(x.id); }
  if (!S.selected || !S.byId.has(S.selected)) S.selected = r.id;
  refresh(); return r;
}
function patch(id, ch) {
  const r = S.byId.get(id);
  if (!r) return;
  Object.assign(r, ch);
  r._v++;
  refresh();
}
const selRec = () => S.byId.get(S.selected) || null;
const activeIcCount = () => S.icQueue.filter(x => x.state === 'waiting').length;

/* ---------- KURALLAR / HOOK / BIRLESIK MUDAHALE MOTORU ---------- */
function runHook(code, request, response) {
  if (!code || !code.trim()) return;
  try { new Function('request', 'response', '"use strict";\n' + code)(request, response); }
  catch (e) { nativeConsole.warn('Inspector Script:', e); toast('Script hatasi: ' + e.message); }
}
function mkRep(r) {
  if (r.regex) { const re = new RegExp(r.match, 'gm'); return s => s.replace(re, r.replace); }
  return s => s.split(r.match).join(r.replace);
}
function applyRules(cur) {
  S.rules.forEach(r => {
    if (!r.on || !r.match) return;
    try {
      const rep = mkRep(r);
      if (r.target === 'req-url') cur.url = rep(cur.url);
      else if (r.target === 'req-header') cur.headers = parseHdr(rep(hdrText(cur.headers)));
      else if (r.target === 'req-body') cur.body = rep(cur.body || '');
    } catch (e) {}
  });
}
function applyResRules(t) {
  S.rules.forEach(r => { if (!r.on || !r.match || r.target !== 'res-body') return; try { t = mkRep(r)(t); } catch (e) {} });
  return t;
}
const hasRules = () => S.rules.some(r => r.on && r.match);

function matchExpr(filterStr, haystack) {
  const f = (filterStr || '').trim();
  if (!f) return true;
  try {
    if (f.length > 2 && f[0] === '/' && f[f.length - 1] === '/') {
      return new RegExp(f.slice(1, -1), 'i').test(haystack);
    }
  } catch (e) {}
  return haystack.toLowerCase().includes(f.toLowerCase());
}

function saveIcCfg() { LS.set('icCfg', S.icCfg); }

function shouldInterceptReq(rec, cur) {
  const c = S.icCfg;
  if (!c.reqOn) return false;
  if (rec && rec.type && c.types[rec.type] === false) return false;
  const m = String(cur.method || 'GET').toUpperCase();
  if (c.methods[m] === false) return false;
  return matchExpr(c.filter, m + ' ' + cur.url + ' ' + (cur.body || ''));
}

function shouldInterceptRes(rec, meta, wasReqIntercepted) {
  const c = S.icCfg;
  if (c.resOn) {
    if (rec && rec.type && c.types[rec.type] === false) return false;
    const m = String(meta.method || 'GET').toUpperCase();
    if (c.methods[m] === false) return false;
    return matchExpr(c.filter, `${m} ${meta.status || ''} ${meta.url || ''} ${meta.body || ''}`);
  }
  return !!(wasReqIntercepted && c.resOn);
}

function shouldInterceptWs(dir, url, data) {
  const c = S.icCfg;
  if (c.types.ws === false) return false;
  if (dir === 'out' && !c.wsOutOn) return false;
  if (dir === 'in' && !c.wsInOn) return false;
  return matchExpr(c.filter, `WS ${dir} ${url} ${data}`);
}

function pushIcItem(item) {
  S.icQueue.unshift(item);
  while (S.icQueue.length > 400) S.icQueue.pop();
  if (!S.icSel || S.icCfg.stepMode) S.icSel = item.uid;
  badges();
  if (S.open && S.tab === 'intercept') renderInterceptLists(true);
}

/* Istek mudahale (iletildiginde listeden silinmez; yaniti ile birlikte listede kalir) */
function holdRequest(rec, cur) {
  return new Promise(resolve => {
    const item = {
      uid: uid(),
      kind: 'request',
      id: rec.id,
      n: rec.n || S.seq,
      netType: rec.type || 'fetch',
      req: clone(cur),
      hdr: hdrText(cur.headers),
      state: 'waiting',
      hasResponse: false,
      responseStatus: null,
      responseStatusText: '',
      responseHdr: '',
      responseBody: '',
      responseSummary: '',
      modified: false,
      modifiedResponse: false,
      resolve,
      t: Date.now()
    };
    pushIcItem(item);
    patch(rec.id, { status: 'held', interceptedReq: true });
    if (!S.open) toast('Istek durduruldu -> Mudahale');
    const to = Number(S.set.icTimeout) || 0;
    if (to > 0) setTimeout(() => { if (item.state === 'waiting') releaseIcItem(item, 'forward'); }, to * 1000);
  });
}

/* Yanit mudahale (hem bagimsiz yanitlari hem de Request Inspect sonrasi gelen yanitlari yakalar) */
function holdResponse(rec, meta, parentReqItem) {
  return new Promise(resolve => {
    const item = {
      uid: uid(),
      kind: 'response',
      parentUid: parentReqItem ? parentReqItem.uid : null,
      id: rec.id,
      n: rec.n || S.seq,
      netType: rec.type || 'fetch',
      method: meta.method,
      url: meta.url,
      status: Number(meta.status) || 200,
      statusText: meta.statusText || 'OK',
      hdr: hdrText(meta.headers || {}),
      body: meta.body == null ? '' : String(meta.body),
      state: 'waiting',
      modifiedResponse: false,
      resolve,
      t: Date.now()
    };
    if (parentReqItem) {
      parentReqItem.hasResponse = true;
      parentReqItem.responseStatus = item.status;
      parentReqItem.responseStatusText = item.statusText;
      parentReqItem.responseHdr = item.hdr;
      parentReqItem.responseBody = item.body;
      parentReqItem.responseSummary = `${item.status} (RESPONSE BEKLIYOR)`;
      parentReqItem.linkedResponseUid = item.uid;
    }
    pushIcItem(item);
    patch(rec.id, { status: 'res-held', hasResponse: true, responseIntercepted: true });
    if (!S.open) toast('Yanit durduruldu -> Mudahale');
    const to = Number(S.set.icTimeout) || 0;
    if (to > 0) setTimeout(() => { if (item.state === 'waiting') releaseIcItem(item, 'forward'); }, to * 1000);
  });
}

/* WebSocket mudahale */
function holdWs(rec, dir, url, data) {
  return new Promise(resolve => {
    const item = {
      uid: uid(),
      kind: dir === 'out' ? 'ws-out' : 'ws-in',
      id: rec.id,
      n: rec.n || S.seq,
      netType: 'ws',
      dir,
      url,
      data: typeof data === 'string' ? data : describeBody(data),
      state: 'waiting',
      resolve,
      t: Date.now()
    };
    pushIcItem(item);
    if (!S.open) toast(`WS ${dir === 'out' ? 'giden' : 'gelen'} mesaj durduruldu`);
    const to = Number(S.set.icTimeout) || 0;
    if (to > 0) setTimeout(() => { if (item.state === 'waiting') releaseIcItem(item, 'forward'); }, to * 1000);
  });
}

function releaseIcItem(item, action) {
  if (!item || item.state !== 'waiting') return;
  item.state = action === 'drop' ? 'dropped' : 'forwarded';

  if (item.kind === 'request') {
    const req = clone(item.req);
    req.headers = parseHdr(item.hdr);
    item.req = req;
    patch(item.id, { status: action === 'drop' ? 'dropped' : 'pending' });
    item.resolve({ action, req, item });
  } else if (item.kind === 'response') {
    const out = {
      action,
      status: Number(item.status) || 200,
      statusText: item.statusText || '',
      headers: parseHdr(item.hdr),
      body: item.body
    };
    if (item.parentUid) {
      const p = S.icQueue.find(x => x.uid === item.parentUid);
      if (p) {
        p.hasResponse = true;
        p.responseStatus = out.status;
        p.responseStatusText = out.statusText;
        p.responseHdr = item.hdr;
        p.responseBody = out.body;
        p.responseSummary = action === 'drop' ? 'RESPONSE DUSURULDU' : `${out.status}${out.statusText ? ' ' + out.statusText : ''} · ${fmtB(out.body.length)}`;
      }
    }
    patch(item.id, { status: action === 'drop' ? 'dropped' : out.status, hasResponse: true, responseIntercepted: true });
    item.resolve(out);
  } else if (item.kind === 'ws-out' || item.kind === 'ws-in') {
    item.resolve({ action, data: item.data });
  }

  /* Siradaki bekleyen ogeye otomatik gec */
  if (S.icCfg.stepMode) {
    const nextWaiting = S.icQueue.find(x => x.state === 'waiting');
    if (nextWaiting) S.icSel = nextWaiting.uid;
  }
  badges();
  if (S.open && S.tab === 'intercept') renderInterceptLists(true);
}

function linkResponseToIntercept(recId, status, statusText, respHeaders, respBody) {
  const it = S.icQueue.find(x => x.kind === 'request' && x.id === recId);
  if (!it) return;
  it.hasResponse = true;
  it.responseStatus = status;
  it.responseStatusText = statusText || '';
  it.responseHdr = hdrText(respHeaders || {});
  it.responseBody = respBody == null ? '' : String(respBody);
  it.responseSummary = `${status}${statusText ? ' ' + statusText : ''} · ${fmtB(it.responseBody.length)}`;
  if (S.open && S.tab === 'intercept') renderInterceptLists(true);
}

async function pipeline(rec, cur) {
  applyRules(cur);
  runHook(S.scripts.before, cur, null);
  let heldItem = null;
  if (shouldInterceptReq(rec, cur)) {
    const d = await holdRequest(rec, cur);
    if (d.action === 'drop') return { dropped: true };
    Object.assign(cur, d.req);
    heldItem = d.item;
  }
  return { dropped: false, cur, heldItem };
}

/* ---------- FETCH (TUM ISTEKLER + EŞZAMANLI REQ/RESP INTERCEPT) ---------- */
if (nativeFetch) W.fetch = async function (input, init) {
  if (!S.on) return nativeFetch(input, init);
  let req;
  try { req = new Request(input, init); } catch (e) { return nativeFetch(input, init); }
  const id = uid(), t0 = performance.now();
  const needBody = S.set.bodies || S.icCfg.reqOn || hasRules() || (S.scripts.before || '').trim();
  let body = '';
  if (!isBodyless(req.method) && needBody) { try { body = await req.clone().text(); } catch (e) {} }
  const orig = { method: req.method, url: req.url, headers: hdrObj(req.headers), body };
  const cur = clone(orig);
  const rec = addRecord({ id, type: 'fetch', method: orig.method, url: orig.url, requestHeaders: orig.headers, requestBody: S.set.bodies ? limit(body) : '', status: 'pending' });
  let out = req;
  let heldReqItem = null;
  let wasReqModified = false;

  try {
    const pipeRes = await pipeline(rec, cur);
    if (pipeRes.dropped) { patch(id, { status: 'dropped' }); throw new TypeError('Inspector Pro: istek dusuruldu'); }
    heldReqItem = pipeRes.heldItem;
    if (JSON.stringify(cur) !== JSON.stringify(orig)) {
      wasReqModified = true;
      try {
        out = new Request(cur.url, {
          method: cur.method, headers: cur.headers, body: isBodyless(cur.method) ? undefined : cur.body,
          credentials: req.credentials, mode: req.mode === 'navigate' ? 'same-origin' : req.mode, redirect: req.redirect,
          cache: req.cache, referrer: req.referrer, referrerPolicy: req.referrerPolicy, keepalive: req.keepalive, signal: req.signal
        });
        patch(id, { method: cur.method, url: cur.url, requestHeaders: cur.headers, requestBody: limit(cur.body), modified: true });
      } catch (e) { out = req; }
    }
  } catch (e) {
    const r = S.byId.get(id); if (!r || r.status !== 'dropped') patch(id, { status: 'error', error: String(e) });
    throw e;
  }

  try {
    let res = await nativeFetch(out);
    const ct = res.headers.get('content-type') || '';
    const textual = isText(ct);
    const respHdrs = hdrObj(res.headers);
    const mustHoldResp = shouldInterceptRes(rec, { method: cur.method, status: res.status, url: cur.url, body: '' }, !!(heldReqItem || wasReqModified));
    const needResBody = mustHoldResp || S.icCfg.resOn || (textual && (S.rules.some(r => r.on && r.target === 'res-body') || (S.scripts.after || '').trim()));

    if (needResBody) {
      let txt0 = '';
      try { txt0 = await res.clone().text(); } catch (e) {}
      let fStatus = res.status, fStatusText = res.statusText, fHdrs = respHdrs, fBody = txt0, modRes = false;

      if (mustHoldResp) {
        const d = await holdResponse(rec, { method: cur.method, url: cur.url, status: res.status, statusText: res.statusText, headers: respHdrs, body: txt0 }, heldReqItem);
        if (d.action === 'drop') {
          patch(id, { status: 'dropped', hasResponse: true, responseHeaders: respHdrs, responseBody: limit(txt0), size: txt0.length, duration: Math.round(performance.now() - t0) });
          linkResponseToIntercept(id, 'DROPPED', '', respHdrs, txt0);
          throw new TypeError('Inspector Pro: yanit dusuruldu');
        }
        fStatus = d.status; fStatusText = d.statusText; fHdrs = d.headers; fBody = d.body;
        modRes = (fStatus !== res.status || fStatusText !== res.statusText || JSON.stringify(fHdrs) !== JSON.stringify(respHdrs) || fBody !== txt0);
      }

      if (textual && (S.rules.some(r => r.on && r.target === 'res-body') || (S.scripts.after || '').trim())) {
        const hookResp = { status: fStatus, headers: fHdrs, body: fBody };
        runHook(S.scripts.after, cur, hookResp);
        const ruled = applyResRules(hookResp.body == null ? fBody : String(hookResp.body));
        if (ruled !== fBody) { fBody = ruled; modRes = true; }
      }

      if (modRes) {
        try { res = new Response(fBody, { status: fStatus, statusText: fStatusText, headers: fHdrs }); } catch (e) {}
      }

      patch(id, {
        status: fStatus, statusText: fStatusText, responseHeaders: fHdrs,
        responseBody: S.set.bodies ? limit(fBody) : '', size: fBody.length,
        mime: ct.split(';')[0], redirected: res.redirected, finalUrl: res.url,
        duration: Math.round(performance.now() - t0), modifiedResponse: modRes, hasResponse: true
      });
      linkResponseToIntercept(id, fStatus, fStatusText, fHdrs, fBody);
      return res;
    }

    const info = { status: res.status, statusText: res.statusText, responseHeaders: respHdrs, mime: ct.split(';')[0], redirected: res.redirected, finalUrl: res.url, duration: Math.round(performance.now() - t0), size: Number(res.headers.get('content-length')) || 0, hasResponse: true };
    patch(id, info);
    linkResponseToIntercept(id, res.status, res.statusText, respHdrs, '');
    if (S.set.bodies && textual && !/event-stream/.test(ct)) {
      res.clone().text().then(t => {
        patch(id, { responseBody: limit(t), size: t.length, hasResponse: true });
        linkResponseToIntercept(id, res.status, res.statusText, respHdrs, t);
      }).catch(() => {});
    }
    return res;
  } catch (e) {
    const r = S.byId.get(id);
    if (!r || r.status !== 'dropped') patch(id, { status: 'error', error: String(e), duration: Math.round(performance.now() - t0) });
    throw e;
  }
};

/* ---------- XHR (TUM ISTEKLER + EŞZAMANLI REQ/RESP INTERCEPT) ---------- */
const xd = new WeakMap();
XHR.prototype.open = function (method, url, async, user, pass) {
  try { xd.set(this, { method: String(method || 'GET').toUpperCase(), url: abs(url), headers: {}, id: uid(), async: async !== false, user, pass }); } catch (e) {}
  return xhrOpen.apply(this, arguments);
};
XHR.prototype.setRequestHeader = function (k, v) {
  const m = xd.get(this); if (m) m.headers[k] = m.headers[k] !== undefined ? m.headers[k] + ', ' + v : v;
  return xhrHeader.call(this, k, v);
};
XHR.prototype.send = function (body) {
  const m = xd.get(this);
  if (!m || !S.on) return xhrSend.call(this, body);
  const self = this, t0 = performance.now();
  const editable = body == null || typeof body === 'string';
  const bstr = editable ? (body || '') : describeBody(body);
  const rec = addRecord({ id: m.id, type: 'xhr', method: m.method, url: m.url, requestHeaders: Object.assign({}, m.headers), requestBody: S.set.bodies ? limit(bstr) : '', status: 'pending' });
  let heldReqItem = null;
  let wasReqModified = false;

  /* Eger Response Intercept aciksa XHR yanitini sayfa koduna vermeden once durdurup duzenleyebilmek icin */
  const origOnReady = self.onreadystatechange;
  const listeners = [];
  const origAddEv = self.addEventListener.bind(self);
  self.addEventListener = function (type, fn, opts) {
    if (type === 'load' || type === 'loadend' || type === 'readystatechange') {
      listeners.push({ type, fn, opts });
      return;
    }
    return origAddEv(type, fn, opts);
  };

  const dispatchAll = (ev) => {
    if (typeof self.onreadystatechange === 'function') { try { self.onreadystatechange.call(self, ev); } catch (e) {} }
    listeners.forEach(l => {
      if (l.type === 'readystatechange' || (self.readyState === 4 && (l.type === 'load' || l.type === 'loadend'))) {
        try { l.fn.call(self, ev); } catch (e) {}
      }
    });
  };

  origAddEv('readystatechange', async function (ev) {
    if (self.readyState !== 4) { dispatchAll(ev); return; }
    if (self.__ipDone) return;
    self.__ipDone = true;
    const r0 = S.byId.get(m.id); if (r0 && r0.status === 'dropped') return;

    let rb = '', size = 0;
    try {
      const rtp = self.responseType;
      if (!rtp || rtp === 'text') rb = self.responseText;
      else if (rtp === 'json') rb = safe(self.response);
      else if (self.response) size = self.response.size || self.response.byteLength || 0;
    } catch (e) {}
    let rh = {}; try { rh = hdrObj(parseHdr(self.getAllResponseHeaders())); } catch (e) {}
    let st = self.status || 0, stTxt = self.statusText || '', outBody = rb, modRes = false;

    const mustHoldResp = shouldInterceptRes(rec, { method: m.method, status: st, url: m.url, body: rb }, !!(heldReqItem || wasReqModified));
    if (mustHoldResp) {
      const d = await holdResponse(rec, { method: m.method, url: m.url, status: st, statusText: stTxt, headers: rh, body: rb }, heldReqItem);
      if (d.action === 'drop') {
        patch(m.id, { status: 'dropped', hasResponse: true, responseHeaders: rh, responseBody: limit(rb), duration: Math.round(performance.now() - t0) });
        linkResponseToIntercept(m.id, 'DROPPED', '', rh, rb);
        try { xhrAbort.call(self); } catch (e) {}
        return;
      }
      st = d.status; stTxt = d.statusText; rh = d.headers; outBody = d.body; modRes = true;
      try {
        Object.defineProperty(self, 'status', { configurable: true, get: () => st });
        Object.defineProperty(self, 'statusText', { configurable: true, get: () => stTxt });
        Object.defineProperty(self, 'responseText', { configurable: true, get: () => outBody });
        if (!self.responseType || self.responseType === 'text') Object.defineProperty(self, 'response', { configurable: true, get: () => outBody });
        else if (self.responseType === 'json') Object.defineProperty(self, 'response', { configurable: true, get: () => JSON.parse(outBody) });
      } catch (e) {}
    }

    const finalSize = String(outBody).length || size;
    patch(m.id, { status: st || 'error', statusText: stTxt, responseHeaders: rh, responseBody: S.set.bodies ? limit(outBody) : '', size: finalSize, mime: (rh['content-type'] || '').split(';')[0], finalUrl: self.responseURL, duration: Math.round(performance.now() - t0), modifiedResponse: modRes, hasResponse: true });
    linkResponseToIntercept(m.id, st || 'ERR', stTxt, rh, outBody);
    dispatchAll(ev);
  });

  const go = b => xhrSend.call(self, b);
  if (!(m.async && (S.icCfg.reqOn || hasRules() || (S.scripts.before || '').trim()))) return go(body);
  const cur = { method: m.method, url: m.url, headers: Object.assign({}, m.headers), body: bstr };
  pipeline(rec, cur).then(pipeRes => {
    if (pipeRes.dropped) {
      patch(m.id, { status: 'dropped' });
      try { xhrAbort.call(self); } catch (e) {}
      try { self.dispatchEvent(new ProgressEvent('error')); self.dispatchEvent(new ProgressEvent('loadend')); } catch (e) {}
      return;
    }
    heldReqItem = pipeRes.heldItem;
    const res = pipeRes.cur;
    if (res.method !== m.method || res.url !== m.url || JSON.stringify(res.headers) !== JSON.stringify(m.headers) || res.body !== bstr) {
      wasReqModified = true;
      try {
        xhrOpen.call(self, res.method, res.url, true, m.user, m.pass);
        Object.keys(res.headers).forEach(k => { try { xhrHeader.call(self, k, res.headers[k]); } catch (e) {} });
        patch(m.id, { method: res.method, url: res.url, requestHeaders: res.headers, requestBody: limit(res.body), modified: true });
      } catch (e) {}
    }
    go(editable ? res.body : body);
  }).catch(() => go(body));
};

/* ---------- WebSocket / EventSource / sendBeacon / console ---------- */
if (NativeWS) {
  const WS = function (url, protocols) {
    const ws = protocols === undefined ? new NativeWS(url) : new NativeWS(url, protocols);
    if (!S.on) return ws;
    const wsUrl = String(ws.url || url);
    const rec = addRecord({ type: 'ws', method: 'WS', url: wsUrl, status: 'open', frames: [] });
    const frame = (dir, d) => {
      const t = typeof d === 'string' ? d : describeBody(d);
      rec.frames.push({ dir, t: Date.now(), d: limit(t, 25000) }); if (rec.frames.length > 800) rec.frames.shift();
      rec.size = (rec.size || 0) + t.length; rec.hasResponse = true; rec._v++; refresh();
    };

    const origSend = ws.send.bind(ws);
    ws.send = async function (d) {
      const rawStr = typeof d === 'string' ? d : describeBody(d);
      if (shouldInterceptWs('out', wsUrl, rawStr)) {
        const decision = await holdWs(rec, 'out', wsUrl, d);
        if (decision.action === 'drop') { frame('out', '[DUSURULDU] ' + rawStr); return; }
        frame('out', decision.data);
        return origSend(decision.data);
      }
      frame('out', d);
      return origSend(d);
    };

    const origAdd = ws.addEventListener.bind(ws);
    const origRem = ws.removeEventListener.bind(ws);
    const wrappedMap = new WeakMap();
    const wrapListener = fn => async function (ev) {
      if (!ev || ev.type !== 'message') return fn.call(this, ev);
      const rawStr = typeof ev.data === 'string' ? ev.data : describeBody(ev.data);
      if (shouldInterceptWs('in', wsUrl, rawStr)) {
        const decision = await holdWs(rec, 'in', wsUrl, ev.data);
        if (decision.action === 'drop') { frame('in', '[DUSURULDU] ' + rawStr); return; }
        frame('in', decision.data);
        const proxyEv = new MessageEvent('message', { data: decision.data, origin: ev.origin, lastEventId: ev.lastEventId, source: ev.source, ports: ev.ports });
        return fn.call(this, proxyEv);
      }
      frame('in', ev.data);
      return fn.call(this, ev);
    };
    ws.addEventListener = function (type, listener, opts) {
      if (type === 'message' && typeof listener === 'function') {
        const wfn = wrapListener(listener);
        wrappedMap.set(listener, wfn);
        return origAdd(type, wfn, opts);
      }
      return origAdd(type, listener, opts);
    };
    ws.removeEventListener = function (type, listener, opts) {
      const target = (type === 'message' && wrappedMap.get(listener)) || listener;
      return origRem(type, target, opts);
    };
    let curOnMsg = null, curOnMsgW = null;
    Object.defineProperty(ws, 'onmessage', {
      configurable: true,
      get() { return curOnMsg; },
      set(fn) {
        if (curOnMsgW) origRem('message', curOnMsgW);
        curOnMsg = typeof fn === 'function' ? fn : null;
        curOnMsgW = curOnMsg ? wrapListener(curOnMsg) : null;
        if (curOnMsgW) origAdd('message', curOnMsgW);
      }
    });

    ws.addEventListener('close', e => patch(rec.id, { status: 'closed', statusText: e.code + ' ' + (e.reason || '') }));
    ws.addEventListener('error', () => patch(rec.id, { error: 'WebSocket hatasi' }));
    return ws;
  };
  WS.prototype = NativeWS.prototype;
  ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(k => { try { Object.defineProperty(WS, k, { value: NativeWS[k] }); } catch (e) {} });
  W.WebSocket = WS;
}

if (NativeES) {
  const ES = function (url, opts) {
    const es = opts === undefined ? new NativeES(url) : new NativeES(url, opts);
    if (!S.on) return es;
    const rec = addRecord({ type: 'sse', method: 'SSE', url: abs(url), status: 'open', frames: [] });
    es.addEventListener('message', e => {
      rec.frames.push({ dir: 'in', t: Date.now(), d: limit(e.data, 20000) });
      rec.responseBody = rec.frames.map(f => f.d).join('\n');
      rec.size = rec.responseBody.length;
      rec.hasResponse = true;
      rec._v++;
      refresh();
    });
    es.addEventListener('error', () => patch(rec.id, { status: 'closed' }));
    return es;
  };
  ES.prototype = NativeES.prototype;
  W.EventSource = ES;
}

if (nativeBeacon) navigator.sendBeacon = function (url, data) {
  if (S.on) addRecord({ type: 'beacon', method: 'POST', url: abs(url), requestBody: limit(describeBody(data)), status: 'sent' });
  return nativeBeacon(url, data);
};

/* PerformanceObserver ile sayfa ici img/script/css/fetch/resource ag isteklerini de kacirmadan yakala */
try {
  if (W.PerformanceObserver) {
    const po = new PerformanceObserver(list => {
      if (!S.on) return;
      list.getEntries().forEach(e => {
        if (e.initiatorType === 'xmlhttprequest' || e.initiatorType === 'fetch' || e.initiatorType === 'beacon') return;
        const u = e.name;
        if (!u || u.startsWith('data:') || u.startsWith('blob:')) return;
        if (S.requests.some(r => r.url === u && Math.abs(r.time - (performance.timeOrigin + e.startTime)) < 1500)) return;
        addRecord({
          type: 'net',
          method: 'GET',
          url: u,
          status: e.responseStatus || 200,
          duration: Math.round(e.duration || 0),
          size: e.transferSize || e.encodedBodySize || 0,
          mime: e.initiatorType || 'resource',
          hasResponse: true
        });
      });
    });
    po.observe({ type: 'resource', buffered: true });
  }
} catch (e) {}

const consPush = (lvl, args) => {
  let t = ''; try { t = args.map(a => typeof a === 'string' ? a : safe(a)).join(' '); } catch (e) { t = String(args); }
  S.cons.push({ lvl, t: limit(t, 3000), time: Date.now() }); if (S.cons.length > 300) S.cons.shift();
  if (S.open && S.tab === 'page' && S.pg === 'console') consRefresh();
};
['log', 'info', 'warn', 'error', 'debug'].forEach(k => { console[k] = function () { consPush(k, [].slice.call(arguments)); return nativeConsole[k].apply(null, arguments); }; });
W.addEventListener('error', e => consPush('error', [(e.message || 'error') + (e.filename ? ' @ ' + e.filename + ':' + e.lineno : '')]));
W.addEventListener('unhandledrejection', e => consPush('error', ['Unhandled rejection: ' + (e.reason && e.reason.message || e.reason)]));

/* ---------- HAM GONDERIM ---------- */
async function sendRaw(o, type) {
  const method = String(o.method || 'GET').toUpperCase();
  const url = abs(String(o.url || '').trim());
  if (!o.url || !String(o.url).trim()) throw new Error('URL gerekli.');
  const headers = typeof o.headers === 'string' ? parseHdr(o.headers) : (o.headers || {});
  const id = uid(), t0 = performance.now();
  const rec = type === 'silent' ? null : addRecord({ id, type: type || 'manual', method, url, requestHeaders: headers, requestBody: limit(o.body || ''), status: 'sending' });
  try {
    const res = await nativeFetch(url, { method, headers, body: isBodyless(method) ? undefined : o.body, credentials: o.cred || 'same-origin', redirect: o.redirect || 'follow' });
    const ct = res.headers.get('content-type') || '';
    let text = '', size = 0;
    if (isText(ct)) { text = await res.text(); size = text.length; } else { size = (await res.arrayBuffer()).byteLength; text = '[ikili icerik ' + fmtB(size) + ' · ' + ct + ']'; }
    const out = { status: res.status, statusText: res.statusText, headers: hdrObj(res.headers), body: text, size, ms: Math.round(performance.now() - t0), url: res.url, redirected: res.redirected, mime: ct.split(';')[0], type: res.type };
    if (rec) patch(id, { status: res.status, statusText: res.statusText, responseHeaders: out.headers, responseBody: limit(text), size, mime: out.mime, duration: out.ms, finalUrl: res.url, hasResponse: true });
    return out;
  } catch (e) { if (rec) patch(id, { status: 'error', error: String(e), duration: Math.round(performance.now() - t0) }); throw e; }
}

/* ================= ARAYUZ ================= */
const CSS = `
:host{all:initial;--bg:#0f1319;--bg2:#161c25;--bg3:#1f2733;--line:#2a3342;--txt:#e7ebf2;--mut:#93a0b5;--acc:#ff8a3d;--acc2:#3a2412;--ok:#3fb68b;--err:#ef5b5b;--warn:#e5b84b;--inp:#0a0e14;--sel:#233044;--fs:13px;--pw:680px;--ph:720px}
:host([data-theme=light]){--bg:#f5f6f8;--bg2:#fff;--bg3:#e8ecf2;--line:#d2d9e4;--txt:#1b2330;--mut:#5b687d;--acc:#d4601a;--acc2:#fde8d7;--ok:#1b8c66;--err:#cf3a3a;--warn:#9c7200;--inp:#fff;--sel:#dfe7f2}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
button,input,select,textarea{font:inherit;color:inherit}
.hidden{display:none!important}
.sym{display:inline-flex;align-items:center;justify-content:center;vertical-align:middle;line-height:1}
#launcher{position:fixed;z-index:2147483647;right:14px;bottom:calc(14px + env(safe-area-inset-bottom,0px));width:52px;height:52px;border-radius:50%;border:2px solid #ffffff33;background:var(--acc);color:#1a0d02;font:800 15px/1 system-ui,sans-serif;box-shadow:0 6px 22px #0008;cursor:pointer;touch-action:none;user-select:none;display:flex;align-items:center;justify-content:center}
#launcher .bd{position:absolute;top:-4px;right:-4px;min-width:20px;height:20px;padding:0 5px;border-radius:10px;background:var(--err);color:#fff;font:700 11px/20px system-ui;text-align:center}
#launcher .bd:empty{display:none}
#panel{position:fixed;z-index:2147483646;left:0;right:0;bottom:var(--vvb,0px);height:min(84dvh,calc(var(--vvh,100dvh) - 10px));display:flex;flex-direction:column;background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:16px 16px 0 0;box-shadow:0 -10px 40px #0009;font:var(--fs)/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow:hidden;padding-bottom:env(safe-area-inset-bottom,0px)}
@media(min-width:700px){#panel{left:auto;right:16px;bottom:calc(78px + var(--vvb,0px));width:min(var(--pw),calc(100vw - 32px));height:min(var(--ph),calc(var(--vvh,100dvh) - 100px));border-radius:14px;resize:both}}
#panel.full{left:0;right:0;top:0;bottom:var(--vvb,0px);width:auto;height:auto;border:0;border-radius:0;resize:none;padding-top:env(safe-area-inset-top,0px)}
.top{display:flex;align-items:center;gap:6px;padding:6px 8px;background:var(--bg2);border-bottom:1px solid var(--line)}
.brand{font-weight:800;margin-right:auto;letter-spacing:.2px;display:flex;align-items:center;gap:6px}
.brand small{font-weight:500;color:var(--mut)}
.stat{color:var(--mut);font-size:11px;white-space:nowrap}
.b{min-height:32px;padding:4px 10px;border-radius:8px;border:1px solid var(--line);background:var(--bg3);cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;justify-content:center;gap:5px}
.b:active{filter:brightness(1.25)}
.b.on,.b.pri{background:var(--acc);border-color:var(--acc);color:#1a0d02;font-weight:700}
.b.dng{color:var(--err);border-color:var(--err)}
.b.sm{min-height:27px;padding:2px 8px;font-size:12px}
.ic{min-width:34px;padding:4px 7px;font-size:14px}
#tabs{display:flex;gap:2px;overflow-x:auto;background:var(--bg2);border-bottom:1px solid var(--line);scrollbar-width:none;padding:0 4px}
#tabs::-webkit-scrollbar{display:none}
#tabs button{flex:none;min-height:38px;padding:0 11px;border:0;border-bottom:3px solid transparent;background:none;color:var(--mut);cursor:pointer;position:relative;font-weight:600;display:inline-flex;align-items:center;gap:4px}
#tabs button.on{color:var(--txt);border-bottom-color:var(--acc)}
#tabs .tb{margin-left:3px;padding:0 6px;border-radius:9px;background:var(--bg3);color:var(--txt);font-size:11px}
#tabs .tb.hot{background:var(--err);color:#fff}
#body{flex:1;min-height:0;overflow:auto;-webkit-overflow-scrolling:touch}
#body.flush{overflow:hidden}
.pad{padding:10px}
label{display:block;margin:8px 0 4px;color:var(--mut);font-size:12px}
label.ck{display:flex;align-items:center;gap:7px;color:var(--txt);font-size:inherit;margin:6px 0;min-height:28px;cursor:pointer}
input:not([type=checkbox]),textarea,select{width:100%;min-width:0;padding:7px 9px;background:var(--inp);color:var(--txt);border:1px solid var(--line);border-radius:8px;outline:none}
input:focus,textarea:focus,select:focus{border-color:var(--acc)}
input[type=checkbox]{width:16px;height:16px;accent-color:var(--acc);flex:none}
textarea{min-height:74px;resize:vertical;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre;overflow:auto}
textarea.wrap{white-space:pre-wrap}
.row{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:6px 0}
.row>.grow{flex:1;min-width:120px}
.mut{color:var(--mut)}.hint{color:var(--mut);font-size:12px;margin:6px 0}
.empty{color:var(--mut);padding:18px 10px;text-align:center}
.bar{display:flex;gap:6px;padding:7px 8px 0}
.filters{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;padding:6px 8px 0}
.filters .ck{margin:0;min-height:28px;font-size:12px}
.tools{padding:6px 8px;overflow-x:auto;scrollbar-width:none;flex-wrap:nowrap}
.hist{display:flex;flex-direction:column;height:100%}
.split{flex:1;min-height:0;display:grid;border-top:1px solid var(--line)}
.list,.detail{overflow:auto;min-width:0;-webkit-overflow-scrolling:touch}
.narrow .split{grid-template-columns:1fr}
.narrow .hist.dv>.bar,.narrow .hist.dv>.filters,.narrow .hist.dv>.ic-settings-box{display:none}
.narrow .split.list .detail,.narrow .split.detail .list{display:none}
.wide .split{grid-template-columns:minmax(220px,42%) 1fr}
.wide .list{border-right:1px solid var(--line)}
.wide .back{display:none}
.it{padding:8px 10px;border-bottom:1px solid var(--line);cursor:pointer;min-width:0}
.it.sel{background:var(--sel);box-shadow:inset 3px 0 var(--acc)}
.l1{display:flex;align-items:center;gap:5px;min-width:0;flex-wrap:nowrap}
.path{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.l2{color:var(--mut);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
.m{font:700 10px ui-monospace,Menlo,monospace;padding:1px 5px;border-radius:4px;background:var(--bg3);flex:none}
.m-POST,.m-PUT,.m-PATCH{color:var(--warn)}.m-DELETE{color:var(--err)}.m-GET{color:var(--ok)}.m-WS{color:#6ab0ff}
.st{font:700 10px ui-monospace,Menlo,monospace;padding:1px 5px;border-radius:4px;background:var(--bg3);color:var(--mut);flex:none}
.st.s2{color:var(--ok)}.st.s3{color:#6ab0ff}.st.s4{color:var(--warn)}.st.s5,.st.er{color:var(--err)}.st.hl{color:#1a0d02;background:var(--acc)}
.tag{font:700 9.5px ui-monospace,Menlo,monospace;padding:1px 5px;border-radius:4px;white-space:nowrap;flex:none}
.tag-req{background:#ff8a3d24;color:var(--acc);border:1px solid #ff8a3d66}
.tag-res{background:#3fb68b24;color:var(--ok);border:1px solid #3fb68b66}
.tag-ws{background:#6ab0ff24;color:#6ab0ff;border:1px solid #6ab0ff66}
.tag-wait{background:var(--acc);color:#1a0d02;font-weight:800}
.tag-done{background:var(--bg3);color:var(--mut)}
.tag-bearer{background:#e5b84b26;color:var(--warn);border:1px solid #e5b84b66}
.detail{padding:10px}
.dh{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.url{font:12px ui-monospace,Menlo,monospace;overflow-wrap:anywhere;color:var(--mut);margin:4px 0 8px}
details{border:1px solid var(--line);border-radius:9px;margin:8px 0;background:var(--bg2)}
summary{padding:8px 10px;cursor:pointer;font-weight:700;list-style:none;display:flex;justify-content:space-between;gap:8px}
summary::-webkit-details-marker{display:none}
summary small{color:var(--mut);font-weight:400}
details>div,details>pre{margin:0 10px 10px}
pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;max-height:280px;overflow:auto;background:var(--inp);border:1px solid var(--line);border-radius:8px;padding:8px;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;user-select:text;-webkit-user-select:text}
pre.tall{max-height:60vh}
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{padding:5px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--bg2)}
tr.sel td{background:var(--sel)}tr.odd td{color:var(--warn)}
.chips{display:flex;gap:6px;overflow-x:auto;margin:6px 0;scrollbar-width:none;flex-wrap:wrap}
.chips .b{flex:none}
.sub{display:flex;gap:4px;overflow-x:auto;padding:8px 8px 0;scrollbar-width:none}
.sub button{flex:none;min-height:30px;padding:0 11px;border-radius:16px;border:1px solid var(--line);background:var(--bg2);cursor:pointer}
.sub button.on{background:var(--acc);border-color:var(--acc);color:#1a0d02;font-weight:700}
ins{background:#3fb68b33;text-decoration:none;color:var(--ok)}del{background:#ef5b5b33;color:var(--err);text-decoration:line-through}
.diff{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 ui-monospace,Menlo,monospace;background:var(--inp);border:1px solid var(--line);border-radius:8px;padding:8px;max-height:55vh;overflow:auto}
.diff .ln{display:block}.diff .ln.a{background:#3fb68b22}.diff .ln.d{background:#ef5b5b22}
.cl{display:flex;gap:6px;padding:3px 0;border-bottom:1px solid var(--line);font:12px ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
.cl.warn{color:var(--warn)}.cl.error{color:var(--err)}.cl.info{color:#6ab0ff}
.fr{padding:4px 7px;border-radius:5px;margin:3px 0;font:12px ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
.fr.in{background:#3fb68b1f}.fr.out{background:#ff8a3d1f}
.card{border:1px solid var(--line);background:var(--bg2);border-radius:10px;padding:10px;margin:8px 0}
.card h4{margin:0 0 6px;font-size:13px;display:flex;align-items:center;gap:6px}
.ic-switches{display:grid;grid-template-columns:repeat(4,1fr);gap:5px;padding:7px 8px 0}
@media(max-width:600px){.ic-switches{grid-template-columns:repeat(2,1fr)}}
.ic-settings-box{margin:6px 8px 0;padding:8px;border:1px solid var(--line);border-radius:9px;background:var(--bg2)}
.ic-grid{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:12px}
#toast{position:fixed;z-index:2147483647;left:50%;bottom:calc(76px + env(safe-area-inset-bottom,0px));transform:translateX(-50%);max-width:88vw;background:#000d;color:#fff;padding:9px 14px;border-radius:10px;font:13px system-ui;pointer-events:none;opacity:0;transition:opacity .2s}
#toast.on{opacity:1}
#hl{position:fixed;z-index:2147483645;pointer-events:none;border:2px solid var(--acc);background:#ff8a3d33;display:none}
`;

const host = D.createElement('div');
host.id = '__ip_host';
const sh = host.attachShadow({ mode: 'open' });
sh.innerHTML = H(`<style>${CSS}</style>
<button id="launcher" title="Inspector Pro">${svgSym('shield')}<span class="bd"></span></button>
<section id="panel" class="hidden narrow">
 <div class="top"><span class="brand">${svgSym('shield')} Inspector Pro<small>${VER}</small></span><span class="stat" id="stat"></span>
  <button class="b ic" data-act="pause" title="Yakalamayi durdur/devam et">${svgSym('pause')}</button>
  <button class="b ic" data-act="full" title="Tam ekran">${svgSym('expand')}</button>
  <button class="b ic" data-act="hide" title="Kucult">${svgSym('close')}</button></div>
 <nav id="tabs"></nav>
 <main id="body"></main>
</section><div id="toast"></div><div id="hl"></div>`);
const $ = q => sh.querySelector(q);
const panel = $('#panel'), launcher = $('#launcher'), bodyEl = $('#body');
const TABS = [
  ['history', 'Istekler'],
  ['intercept', 'Mudahale'],
  ['repeater', 'Repeater'],
  ['intruder', 'Intruder'],
  ['decoder', 'Decoder'],
  ['compare', 'Karsilastir'],
  ['target', 'Hedef'],
  ['page', 'Sayfa'],
  ['rules', 'Kurallar'],
  ['scripts', 'Ek Script'],
  ['guide', 'Kilavuz'],
  ['settings', 'Ayarlar']
];

let toastT = 0;
function toast(m) { const t = $('#toast'); if (!t) return; t.textContent = m; t.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 1800); }
function copy(v, msg) {
  const done = () => toast(msg || 'Kopyalandi');
  const fb = () => { const t = D.createElement('textarea'); t.value = v; t.style.cssText = 'position:fixed;opacity:0'; D.body.appendChild(t); t.select(); try { D.execCommand('copy'); done(); } catch (e) { toast('Kopyalanamadi'); } t.remove(); };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(v).then(done, fb); else fb();
}
function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type: type || 'application/json' }));
  const a = D.createElement('a'); a.href = url; a.download = name; D.documentElement.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function pickFile(accept, cb) {
  const i = D.createElement('input'); i.type = 'file'; i.accept = accept || '';
  i.onchange = () => { const f = i.files[0]; if (!f) return; const rd = new FileReader(); rd.onload = () => cb(String(rd.result), f.name); rd.readAsText(f); };
  i.click();
}

/* ---------- GORUNUM VE BOYUT YONETIMI ---------- */
function applyPanelSize() {
  const presets = { compact: [440, 520], standard: [680, 720], wide: [920, 780] };
  let w = Number(S.set.panelW) || 680, h = Number(S.set.panelH) || 720;
  if (S.set.panelSizePreset && S.set.panelSizePreset !== 'custom' && presets[S.set.panelSizePreset]) {
    [w, h] = presets[S.set.panelSizePreset];
    S.set.panelW = w; S.set.panelH = h;
  }
  w = Math.max(340, Math.min(1800, w));
  h = Math.max(300, Math.min(1300, h));
  host.style.setProperty('--pw', w + 'px');
  host.style.setProperty('--ph', h + 'px');
}
function applyTheme() {
  let t = S.set.theme; if (t === 'auto') t = (W.matchMedia && W.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  host.setAttribute('data-theme', t);
  host.style.setProperty('--fs', (Number(S.set.font) || 13) + 'px');
  applyPanelSize();
}
function fitViewport() {
  const v = W.visualViewport; if (!v) return;
  host.style.setProperty('--vvb', Math.max(0, W.innerHeight - v.height - v.offsetTop) + 'px');
  host.style.setProperty('--vvh', v.height + 'px');
}
function openPanel() {
  if (S.disabledSite) return;
  S.open = true; panel.classList.remove('hidden'); launcher.classList.add('hidden'); renderTabs(); renderTab(); fitViewport();
}
function closePanel() {
  S.open = false; S.full = false; panel.classList.remove('full'); panel.classList.add('hidden'); launcher.classList.remove('hidden');
}
const togglePanel = () => (S.open ? closePanel() : openPanel());
function setFull(v) {
  S.full = v; panel.classList.toggle('full', v);
  const btn = sh.querySelector('[data-act=full]');
  if (btn) btn.innerHTML = H(svgSym(v ? 'shrink' : 'expand'));
}
function badges() {
  const activeHeld = activeIcCount();
  const b = launcher.querySelector('.bd');
  b.textContent = activeHeld ? String(activeHeld) : '';
  const tb = sh.querySelector('[data-tab=intercept] .tb');
  if (tb) { tb.textContent = activeHeld || ''; tb.classList.toggle('hot', !!activeHeld); tb.style.display = activeHeld ? '' : 'none'; }
  const th = sh.querySelector('[data-tab=history] .tb'); if (th) th.textContent = S.requests.length;
  const st = $('#stat'); if (st) st.textContent = (S.on ? 'AKTIF ' : 'DURDU ') + S.requests.length;
  const pb = sh.querySelector('[data-act=pause]');
  if (pb) { pb.classList.toggle('on', !S.on); pb.innerHTML = H(svgSym(S.on ? 'pause' : 'play')); }
}
function renderTabs() {
  const activeHeld = activeIcCount();
  $('#tabs').innerHTML = H(TABS.map(([k, l]) => `<button data-tab="${k}" class="${S.tab === k ? 'on' : ''}">${l}${k === 'history' ? `<span class="tb">${S.requests.length}</span>` : k === 'intercept' ? `<span class="tb ${activeHeld ? 'hot' : ''}" style="${activeHeld ? '' : 'display:none'}">${activeHeld}</span>` : ''}</button>`).join(''));
}
function renderTab() {
  bodyEl.classList.toggle('flush', S.tab === 'history' || S.tab === 'intercept');
  const map = {
    history: renderHistory,
    intercept: renderIntercept,
    repeater: renderRepeater,
    intruder: renderIntruder,
    decoder: renderDecoder,
    compare: renderCompare,
    target: renderTarget,
    page: renderPage,
    rules: renderRules,
    scripts: renderScripts,
    guide: renderGuide,
    settings: renderSettings
  };
  bodyEl.innerHTML = H(map[S.tab]());
  sh.querySelectorAll('[data-tab]').forEach(b => b.classList.toggle('on', b.dataset.tab === S.tab));
  if (S.tab === 'history') renderHistoryLists(true);
  if (S.tab === 'intercept') renderInterceptLists(true);
  if (S.tab === 'page') pageAfter();
  badges();
}
function liveUpdate() {
  badges();
  if (S.open && S.tab === 'history') renderHistoryLists();
  else if (S.open && S.tab === 'intercept') renderInterceptLists();
  else if (S.open && S.tab === 'target') renderTab();
  publish();
}

/* ---------- ISTEKLER ---------- */
const stc = r => { const s = r.status; if (typeof s === 'number') return 's' + Math.floor(s / 100); if (s === 'error' || s === 'dropped') return 'er'; if (s === 'held' || s === 'res-held') return 'hl'; return ''; };
const stLabel = r => r.status === 0 ? 'ERR' : String(r.status);
function filtered() {
  const F = S.f; let re = null, q = F.q.toLowerCase();
  if (F.q && F.regex) { try { re = new RegExp(F.q, 'i'); } catch (e) { re = null; } }
  return S.requests.filter(r => {
    if (F.method && r.method !== F.method) return false;
    if (F.type && r.type !== F.type) return false;
    if (F.star && !r.star) return false;
    if (F.onlyBearer && !extractBearerTokens(r).length) return false;
    if (F.host && hostOf(r.url) !== F.host) return false;
    if (F.status) { const s = r.status; if (F.status === 'err') { if (!(s === 'error' || s === 0 || s === 'dropped')) return false; } else if (typeof s !== 'number' || String(Math.floor(s / 100)) !== F.status) return false; }
    if (F.q) {
      let hay = r.method + ' ' + r.status + ' ' + r.type + ' ' + r.url;
      if (F.inBody) hay += ' ' + r.requestBody + ' ' + r.responseBody + ' ' + hdrText(r.requestHeaders) + ' ' + hdrText(r.responseHeaders);
      return re ? re.test(hay) : hay.toLowerCase().includes(q);
    }
    return true;
  });
}
function renderHistory() {
  const sel = (k, opts, v) => `<select data-f="${k}">${opts.map(o => `<option value="${o[0]}" ${o[0] === v ? 'selected' : ''}>${o[1]}</option>`).join('')}</select>`;
  return `<div class="hist">
 <div class="bar"><input id="f-q" type="search" placeholder="URL, method, durum, govde, Bearer ara..." value="${esc(S.f.q)}" data-f="q"><button class="b ${S.showF ? 'on' : ''}" data-act="filters">${svgSym('sliders')} Filtre</button></div>
 <div class="filters ${S.showF ? '' : 'hidden'}">
  ${sel('method', [['', 'Method'], ['GET', 'GET'], ['POST', 'POST'], ['PUT', 'PUT'], ['PATCH', 'PATCH'], ['DELETE', 'DELETE'], ['OPTIONS', 'OPTIONS'], ['WS', 'WS'], ['SSE', 'SSE']], S.f.method)}
  ${sel('status', [['', 'Durum'], ['2', '2xx'], ['3', '3xx'], ['4', '4xx'], ['5', '5xx'], ['err', 'Hata']], S.f.status)}
  ${sel('type', [['', 'Tur'], ['fetch', 'fetch'], ['xhr', 'xhr'], ['ws', 'websocket'], ['sse', 'sse'], ['beacon', 'beacon'], ['manual', 'manuel'], ['intruder', 'intruder'], ['net', 'ag'], ['import', 'ice aktarilan']], S.f.type)}
  <label class="ck"><input type="checkbox" data-f="star" ${S.f.star ? 'checked' : ''}>${svgSym('star')} yildizli</label>
  <label class="ck"><input type="checkbox" data-f="regex" ${S.f.regex ? 'checked' : ''}>regex</label>
  <label class="ck"><input type="checkbox" data-f="inBody" ${S.f.inBody ? 'checked' : ''}>govdede ara</label>
  <label class="ck" style="grid-column:1/-1"><input type="checkbox" data-f="onlyBearer" ${S.f.onlyBearer ? 'checked' : ''}>${svgSym('key')} Sadece Bearer token icerenler</label>
  ${S.f.host ? `<button class="b sm" data-act="hostclear" style="grid-column:1/-1">host: ${esc(S.f.host)} ${svgSym('close')}</button>` : ''}
 </div>
 <div class="bar tools row"><button class="b sm" data-act="har">HAR Indir</button><button class="b sm" data-act="exp-json">JSON</button><button class="b sm" data-act="csv">CSV</button><button class="b sm" data-act="import">Ice aktar</button><button class="b sm" data-act="clear-star">Yildiz temizle</button><button class="b sm dng" data-act="clear">Temizle</button></div>
 <div class="split ${S.view}" id="split"><div class="list" id="ip-list"></div><div class="detail" id="ip-detail"></div></div></div>`;
}
function itemHTML(r) {
  const hasRes = !!(r.hasResponse || (typeof r.status === 'number' && r.status > 0) || r.responseBody || (r.responseHeaders && Object.keys(r.responseHeaders).length));
  const hasBearer = extractBearerTokens(r).length > 0;
  return `<div class="it ${r.id === S.selected ? 'sel' : ''}" data-id="${esc(r.id)}"><div class="l1"><b class="m m-${esc(r.method)}">${esc(r.method)}</b><span class="st ${stc(r)}">${esc(stLabel(r))}</span>${hasRes ? '<span class="tag tag-res">RESPONSE</span>' : ''}${hasBearer ? '<span class="tag tag-bearer">BEARER</span>' : ''}${r.star ? svgSym('star') : ''}<span class="path">${esc(pathOf(r.url))}</span></div><div class="l2">#${r.n} · ${esc(hostOf(r.url))} · ${esc(r.type)}${r.modified ? ' · istek degisti' : ''}${r.modifiedResponse ? ' · yanit degisti' : ''}${r.duration ? ' · ' + r.duration + ' ms' : ''}${r.size ? ' · ' + fmtB(r.size) : ''}</div></div>`;
}
let detKey = '';
function renderHistoryLists(force) {
  const list = $('#ip-list'), det = $('#ip-detail'); if (!list) return;
  const items = filtered(), top = list.scrollTop;
  list.innerHTML = H(items.length ? items.slice(0, 500).map(itemHTML).join('') + (items.length > 500 ? `<div class="empty">+${items.length - 500} kayit daha — filtreyi daralt</div>` : '') : '<div class="empty">Henuz istek yok.<br>Sayfada gezin veya bir islem yapin; tum fetch, XHR, WebSocket, SSE, beacon ve kaynak trafigi burada gorunur.</div>');
  list.scrollTop = top;
  const r = selRec(), key = r ? r.id + ':' + r._v + ':' + S.set.pretty + ':' + S.set.mask + ':' + S.set.showBearer : '';
  if (force || key !== detKey) {
    detKey = key; const dt = det.scrollTop;
    det.innerHTML = H(r ? detailHTML(r) : '<div class="empty">Bir istek sec.</div>');
    det.scrollTop = force ? 0 : dt;
  }
  $('#split').className = 'split ' + S.view;
  const hs = sh.querySelector('.hist'); if (hs) hs.classList.toggle('dv', S.view === 'detail');
}
function bodyView(t) {
  t = String(t || ''); if (!t) return '(bos)';
  if (S.set.pretty && /^\s*[\[{]/.test(t)) t = prettyJSON(t);
  return t.length > 40000 ? t.slice(0, 40000) + '\n... (' + fmtB(t.length) + ' — tamami icin Kopyala)' : t;
}
function findJWT(r) {
  const hay = hdrText(r.requestHeaders) + '\n' + r.requestBody + '\n' + hdrText(r.responseHeaders) + '\n' + r.responseBody;
  return [...new Set(hay.match(/eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*/g) || [])].slice(0, 5);
}
function jwtDecode(t) {
  try { const p = t.split('.'); const d = s => decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)))); return prettyJSON(d(p[0])) + '\n' + prettyJSON(d(p[1])); } catch (e) { return 'cozulemedi'; }
}
function detailHTML(r) {
  let q = []; try { q = [...new URL(r.url).searchParams.entries()]; } catch (e) {}
  const jwts = findJWT(r);
  const bearers = extractBearerTokens(r);
  const rq = shown(r.requestHeaders), rs = shown(r.responseHeaders);
  return `<div class="dh"><button class="b back" data-act="back">${svgSym('back')} Liste</button><div><b class="m m-${esc(r.method)}">${esc(r.method)}</b> <span class="st ${stc(r)}">${esc(stLabel(r))}</span> <span class="mut">${esc(r.statusText || '')}</span></div></div>
<div class="url">${esc(r.url)}</div>
<div class="row"><button class="b sm pri" data-act="to-rp">${svgSym('arrow')} Repeater</button><button class="b sm" data-act="to-in">${svgSym('arrow')} Intruder</button><button class="b sm ${r.star ? 'on' : ''}" data-act="star">${svgSym('star')}</button><button class="b sm" data-act="pretty">${S.set.pretty ? 'Pretty' : 'Raw'}</button><button class="b sm" data-act="host-filter">Host</button><button class="b sm dng" data-act="del">${svgSym('trash')} Sil</button></div>
<div class="row"><select class="grow" data-chg="copyas">
  <option value="">Kopyala...</option>
  <option value="har">HAR Kopyala (Istek + Yanit HAR 1.2)</option>
  <option value="curl">cURL</option>
  <option value="fetch">fetch()</option>
  <option value="py">Python requests</option>
  <option value="rawreq">Ham istek</option>
  <option value="rawres">Ham yanit</option>
  <option value="url">URL</option>
  <option value="resbody">Yanit govdesi</option>
  <option value="reqbody">Istek govdesi</option>
</select>
<select class="grow" data-chg="cmpset"><option value="">Karsilastir...</option><option value="a:res">A &lt;- yanit govdesi</option><option value="b:res">B &lt;- yanit govdesi</option><option value="a:req">A &lt;- istek govdesi</option><option value="b:req">B &lt;- istek govdesi</option><option value="a:hdr">A &lt;- yanit header</option><option value="b:hdr">B &lt;- yanit header</option></select></div>
${bearers.length ? `<details open><summary>Bearer Token (Acik) <small>${bearers.length}</small></summary><div>${bearers.map((b, idx) => `<div style="margin-bottom:6px"><div class="row"><span class="mut">${esc(b.loc)}</span><button class="b sm" data-act="copy-bearer" data-i="${idx}">${svgSym('copy')} Token Kopyala</button></div><pre>${esc(b.full)}</pre></div>`).join('')}</div></details>` : ''}
<details open><summary>Genel</summary><div><table><tr><td>Tur</td><td>${esc(r.type)}${r.modified ? ' · <b>istek degistirildi</b>' : ''}${r.modifiedResponse ? ' · <b>yanit degistirildi</b>' : ''}</td></tr><tr><td>Sure / boyut</td><td>${r.duration || 0} ms · ${fmtB(r.size)}</td></tr><tr><td>MIME</td><td>${esc(r.mime || '-')}</td></tr>${r.finalUrl && r.finalUrl !== r.url ? `<tr><td>Son URL</td><td>${esc(r.finalUrl)}</td></tr>` : ''}${r.error ? `<tr><td>Hata</td><td>${esc(r.error)}</td></tr>` : ''}</table></div></details>
${q.length ? `<details><summary>Query <small>${q.length}</small></summary><div><table>${q.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table></div></details>` : ''}
<details open><summary>Istek header <small>${Object.keys(rq).length}</small></summary><pre>${esc(hdrText(rq)) || '(yok)'}</pre></details>
<details ${r.requestBody ? 'open' : ''}><summary>Istek govdesi <small>${fmtB(r.requestBody.length)}</small></summary><pre>${esc(bodyView(r.requestBody))}</pre></details>
<details open><summary>Yanit header <small>${Object.keys(rs).length}</small></summary><pre>${esc(hdrText(rs)) || '(yok)'}</pre></details>
${(r.type === 'ws' || r.type === 'sse') ? `<details open><summary>Mesajlar <small>${(r.frames || []).length}</small></summary><div>${(r.frames || []).slice(-200).map(f => `<div class="fr ${f.dir}">${f.dir === 'in' ? svgSym('down') : svgSym('up')} ${esc(limit(f.d, 1000))}</div>`).join('') || '(yok)'}</div></details>` : `<details open><summary>Yanit govdesi <small>${fmtB(r.responseBody.length)}</small></summary><pre class="tall">${esc(bodyView(r.responseBody))}</pre></details>`}
${jwts.length ? `<details><summary>JWT Cozumleme <small>${jwts.length}</small></summary><div>${jwts.map(j => `<pre>${esc(jwtDecode(j))}</pre>`).join('<br>')}</div></details>` : ''}
<label>Not</label><textarea class="wrap" data-b="note" style="min-height:50px">${esc(r.note || '')}</textarea>`;
}
const qsafe = v => "'" + String(v == null ? '' : v).replace(/'/g, "'\\''") + "'";
const hdrsOut = r => shown(r.requestHeaders);
function asCurl(r) { let o = 'curl -i -X ' + qsafe(r.method) + ' ' + qsafe(r.url); Object.entries(hdrsOut(r)).forEach(([k, v]) => { o += ' \\\n  -H ' + qsafe(k + ': ' + v); }); if (r.requestBody) o += ' \\\n  --data-raw ' + qsafe(r.requestBody); return o; }
function asFetch(r) { const o = { method: r.method, headers: hdrsOut(r), credentials: 'include' }; if (r.requestBody && !isBodyless(r.method)) o.body = r.requestBody; return 'fetch(' + JSON.stringify(r.url) + ', ' + JSON.stringify(o, null, 2) + ')\n  .then(r => r.text()).then(console.log);'; }
function asPy(r) { return 'import requests\n\nr = requests.request(' + JSON.stringify(r.method) + ', ' + JSON.stringify(r.url) + ',\n    headers=' + JSON.stringify(hdrsOut(r), null, 4) + ',\n    data=' + JSON.stringify(r.requestBody || '') + ')\nprint(r.status_code)\nprint(r.text)'; }
const rawReq = r => { let u; try { u = new URL(r.url); } catch (e) { u = { pathname: r.url, search: '', host: '' }; } return r.method + ' ' + u.pathname + u.search + ' HTTP/1.1\nHost: ' + u.host + '\n' + hdrText(hdrsOut(r)) + '\n\n' + (r.requestBody || ''); };
const rawRes = r => 'HTTP/1.1 ' + r.status + ' ' + (r.statusText || '') + '\n' + hdrText(shown(r.responseHeaders)) + '\n\n' + (r.responseBody || '');
const asHarSingle = r => JSON.stringify(toHAR([r]), null, 2);
function copyAs(k, r) {
  const m = { har: asHarSingle, curl: asCurl, fetch: asFetch, py: asPy, rawreq: rawReq, rawres: rawRes, url: x => x.url, resbody: x => x.responseBody, reqbody: x => x.requestBody };
  if (m[k]) copy(m[k](r), k === 'har' ? 'HAR (Istek + Yanit) panoya kopyalandi' : 'Kopyalandi');
}
function toHAR(list) {
  return { log: { version: '1.2', creator: { name: 'Inspector Pro', version: VER }, entries: list.filter(r => r.type !== 'ws').map(r => {
    let qs = []; try { qs = [...new URL(r.url).searchParams.entries()].map(([name, value]) => ({ name, value })); } catch (e) {}
    const rh = shown(r.requestHeaders), sh2 = shown(r.responseHeaders);
    return { startedDateTime: new Date(r.time).toISOString(), time: r.duration || 0,
      request: { method: r.method, url: r.url, httpVersion: 'HTTP/1.1', headers: Object.entries(rh).map(([name, value]) => ({ name, value })), queryString: qs, cookies: [], headersSize: -1, bodySize: (r.requestBody || '').length, postData: r.requestBody ? { mimeType: rh['content-type'] || rh['Content-Type'] || 'text/plain', text: r.requestBody } : undefined },
      response: { status: Number(r.status) || 0, statusText: r.statusText || '', httpVersion: 'HTTP/1.1', headers: Object.entries(sh2).map(([name, value]) => ({ name, value })), cookies: [], content: { size: r.size || 0, mimeType: r.mime || 'text/plain', text: r.responseBody || '' }, redirectURL: '', headersSize: -1, bodySize: r.size || 0 },
      cache: {}, timings: { send: 0, wait: r.duration || 0, receive: 0 } };
  }) } };
}
function importData(text) {
  try {
    const j = JSON.parse(text); let n = 0;
    if (j.log && j.log.entries) {
      j.log.entries.forEach(e => { const h = a => { const o = {}; (a || []).forEach(x => { o[x.name] = x.value; }); return o; };
        addRecord({ type: 'import', method: e.request.method, url: e.request.url, requestHeaders: h(e.request.headers), requestBody: e.request.postData ? e.request.postData.text || '' : '', status: e.response.status, statusText: e.response.statusText, responseHeaders: h(e.response.headers), responseBody: e.response.content ? e.response.content.text || '' : '', mime: e.response.content ? e.response.content.mimeType : '', duration: Math.round(e.time || 0), size: e.response.content ? e.response.content.size : 0, time: Date.parse(e.startedDateTime) || Date.now(), hasResponse: true }); n++; });
    } else if (j.app === 'inspector-pro') { j.requests.slice().reverse().forEach(r => { delete r.id; r.type = r.type || 'import'; addRecord(r); n++; }); }
    toast(n + ' kayit ice aktarildi'); renderTab();
  } catch (e) { toast('Dosya okunamadi: ' + e.message); }
}

/* ---------- MUDAHALE (ISTEK + YANIT + WS BIRLESIK LISTE VE AYARLAR) ---------- */
function icFiltered() {
  const f = S.icCfg.filter.trim();
  if (!f) return S.icQueue;
  return S.icQueue.filter(h => {
    const hay = h.kind === 'request'
      ? `REQUEST ${h.req.method} ${h.req.url} ${h.state} ${h.responseSummary || ''}`
      : h.kind === 'response'
        ? `RESPONSE ${h.method} ${h.status} ${h.url} ${h.state}`
        : `WS ${h.dir} ${h.url} ${h.data} ${h.state}`;
    return matchExpr(f, hay);
  });
}

function renderIntercept() {
  const c = S.icCfg;
  return `<div class="hist">
  <div class="ic-switches">
    <button class="b sm ${c.reqOn ? 'pri' : ''}" data-act="ic-toggle-req">Request Inspect: ${c.reqOn ? 'ACIK' : 'KAPALI'}</button>
    <button class="b sm ${c.resOn ? 'pri' : ''}" data-act="ic-toggle-res">Response Inspect: ${c.resOn ? 'ACIK' : 'KAPALI'}</button>
    <button class="b sm ${c.wsOutOn ? 'pri' : ''}" data-act="ic-toggle-wsout">WS Giden: ${c.wsOutOn ? 'ACIK' : 'KAPALI'}</button>
    <button class="b sm ${c.wsInOn ? 'pri' : ''}" data-act="ic-toggle-wsin">WS Gelen: ${c.wsInOn ? 'ACIK' : 'KAPALI'}</button>
  </div>
  <div class="bar">
    <input type="search" placeholder="Mudahale filtresi (URL, method, status, /regex/)..." value="${esc(c.filter)}" data-b="icCfg.filter">
    <button class="b sm ${c.showSettings ? 'on' : ''}" data-act="ic-toggle-settings">${svgSym('sliders')} Ayarlar</button>
  </div>
  <div class="ic-settings-box ${c.showSettings ? '' : 'hidden'}">
    <div class="ic-grid">
      <b>Yakalanacak Turler:</b>
      <label class="ck" style="margin:0"><input type="checkbox" data-ic-type="fetch" ${c.types.fetch ? 'checked' : ''}>fetch</label>
      <label class="ck" style="margin:0"><input type="checkbox" data-ic-type="xhr" ${c.types.xhr ? 'checked' : ''}>XHR</label>
      <label class="ck" style="margin:0"><input type="checkbox" data-ic-type="ws" ${c.types.ws ? 'checked' : ''}>WebSocket</label>
      <label class="ck" style="margin:0"><input type="checkbox" data-b="icCfg.stepMode" ${c.stepMode ? 'checked' : ''}>Oto odak (Siradaki bekleyene gec)</label>
    </div>
    <div class="ic-grid" style="margin-top:4px">
      <b>Methodlar:</b>
      ${['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map(m => `<label class="ck" style="margin:0"><input type="checkbox" data-ic-method="${m}" ${c.methods[m] !== false ? 'checked' : ''}>${m}</label>`).join('')}
    </div>
  </div>
  <div class="bar tools row">
    <button class="b sm pri" data-act="ic-fwd">${svgSym('check')} Secileni Ilet</button>
    <button class="b sm dng" data-act="ic-drop">${svgSym('close')} Secileni Dusur</button>
    <button class="b sm" data-act="ic-fwdall">Bekleyenleri Ilet (${activeIcCount()})</button>
    <button class="b sm" data-act="ic-dropall">Bekleyenleri Dusur</button>
    <button class="b sm" data-act="ic-clear-done">Islenenleri Temizle</button>
  </div>
  <div class="split ${S.icView}" id="ic-split">
    <div class="list" id="ic-list"></div>
    <div class="detail" id="ic-detail"></div>
  </div>
</div>`;
}

function icItemHTML(h) {
  const isSel = h.uid === S.icSel;
  const stBadge = h.state === 'waiting'
    ? '<span class="tag tag-wait">BEKLIYOR</span>'
    : h.state === 'dropped'
      ? '<span class="st er">DUSURULDU</span>'
      : '<span class="tag tag-done">ILETILDI</span>';

  if (h.kind === 'request') {
    const resBadge = h.hasResponse
      ? `<span class="tag tag-res">RESPONSE${h.responseSummary ? ' · ' + esc(h.responseSummary) : ''}</span>`
      : '';
    return `<div class="it ${isSel ? 'sel' : ''}" data-ic-uid="${esc(h.uid)}">
      <div class="l1"><span class="tag tag-req">REQUEST</span><b class="m m-${esc(h.req.method)}">${esc(h.req.method)}</b>${stBadge}${resBadge}<span class="path">${esc(pathOf(h.req.url))}</span></div>
      <div class="l2">#${h.n || ''} · ${esc(hostOf(h.req.url))} · ${esc(h.netType)}</div>
    </div>`;
  }
  if (h.kind === 'response') {
    return `<div class="it ${isSel ? 'sel' : ''}" data-ic-uid="${esc(h.uid)}">
      <div class="l1"><span class="tag tag-res">RESPONSE</span><b class="m m-${esc(h.method)}">${esc(h.method)}</b><span class="st s${Math.floor(h.status / 100)}">${h.status}</span>${stBadge}<span class="path">${esc(pathOf(h.url))}</span></div>
      <div class="l2">#${h.n || ''} · ${esc(hostOf(h.url))} · ${esc(h.netType)} · ${fmtB((h.body || '').length)}</div>
    </div>`;
  }
  const dirLabel = h.dir === 'out' ? 'WS GIDEN' : 'WS GELEN';
  return `<div class="it ${isSel ? 'sel' : ''}" data-ic-uid="${esc(h.uid)}">
    <div class="l1"><span class="tag tag-ws">${dirLabel}</span>${stBadge}<span class="path">${esc(limit(h.data, 80))}</span></div>
    <div class="l2">#${h.n || ''} · ${esc(hostOf(h.url))} · WebSocket</div>
  </div>`;
}

function icDetailHTML(h) {
  const isWaiting = h.state === 'waiting';
  const navBar = `<div class="dh">
    <button class="b back" data-act="ic-back">${svgSym('back')} Liste</button>
    <div>
      ${h.kind === 'request' ? '<span class="tag tag-req">REQUEST</span>' : h.kind === 'response' ? '<span class="tag tag-res">RESPONSE</span>' : `<span class="tag tag-ws">${h.dir === 'out' ? 'WS GIDEN' : 'WS GELEN'}</span>`}
      <span class="mut">#${h.n || ''} · ${h.state === 'waiting' ? 'Duzenlenebilir (Bekliyor)' : h.state === 'dropped' ? 'Dusuruldu' : 'Iletildi (Listede Korunuyor)'}</span>
    </div>
  </div>
  <div class="url">${esc(h.kind === 'request' ? h.req.url : h.url)}</div>
  <div class="row">
    ${isWaiting ? `<button class="b sm pri" data-act="ic-fwd">${svgSym('check')} Ilet</button><button class="b sm dng" data-act="ic-drop">${svgSym('close')} Dusur</button>` : '<span class="mut">Iletildi · kayit listede tutuluyor.</span>'}
    ${h.kind !== 'ws-out' && h.kind !== 'ws-in' ? `<button class="b sm" data-act="ic-rp">${svgSym('arrow')} Repeater</button>` : ''}
    ${S.byId.has(h.id) ? `<button class="b sm" data-act="ic-to-hist">${svgSym('arrow')} Isteklerde Ac</button>` : ''}
  </div>`;

  if (h.kind === 'request') {
    const liveRec = S.byId.get(h.id);
    const liveResHdr = h.responseHdr || (liveRec ? hdrText(liveRec.responseHeaders) : '');
    const liveResBody = h.responseBody || (liveRec ? liveRec.responseBody : '');
    return `${navBar}
    <label>Method</label>
    <select data-b="ic.method" ${isWaiting ? '' : 'disabled'}>${['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map(m => `<option ${h.req.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select>
    <label>URL</label>
    <input data-b="ic.url" value="${esc(h.req.url)}" ${isWaiting ? '' : 'readonly'}>
    <label>Istek Header</label>
    <textarea data-b="ic.hdr" ${isWaiting ? '' : 'readonly'}>${esc(h.hdr)}</textarea>
    <label>Istek Govdesi</label>
    <textarea data-b="ic.body" ${isWaiting ? '' : 'readonly'}>${esc(h.req.body)}</textarea>
    ${h.hasResponse ? `<details open><summary>Gelen Yanit (RESPONSE) <small>${esc(h.responseSummary || '')}</small></summary><div><label>Yanit Header</label><pre>${esc(liveResHdr) || '(yok)'}</pre><label>Yanit Govdesi</label><pre class="tall">${esc(bodyView(liveResBody))}</pre></div></details>` : '<p class="hint">Istek iletildiginde Response Inspect aciksa yaniti da yakalanip durdurulur; kapaliysa yanit geldiginde burada gorunur.</p>'}`;
  }

  if (h.kind === 'response') {
    return `${navBar}
    <div class="row">
      <div style="width:110px"><label>Durum Kodu</label><input type="number" data-b="ic.status" value="${h.status}" ${isWaiting ? '' : 'readonly'}></div>
      <div class="grow"><label>Durum Metni</label><input data-b="ic.statusText" value="${esc(h.statusText)}" ${isWaiting ? '' : 'readonly'}></div>
    </div>
    <label>Yanit Header</label>
    <textarea data-b="ic.hdr" ${isWaiting ? '' : 'readonly'}>${esc(h.hdr)}</textarea>
    <label>Yanit Govdesi (Duzenle ve Ilet)</label>
    <textarea data-b="ic.body" style="min-height:160px" ${isWaiting ? '' : 'readonly'}>${esc(h.body)}</textarea>`;
  }

  return `${navBar}
  <label>WebSocket Mesaj Icerigi (${h.dir === 'out' ? 'Istemci -> Sunucu' : 'Sunucu -> Istemci'})</label>
  <textarea data-b="ic.data" style="min-height:180px" ${isWaiting ? '' : 'readonly'}>${esc(h.data)}</textarea>`;
}

function renderInterceptLists(force) {
  const list = $('#ic-list'), det = $('#ic-detail');
  if (!list || !det) return;
  const items = icFiltered();
  if (!S.icSel && items[0]) S.icSel = items[0].uid;
  const sel = items.find(x => x.uid === S.icSel) || S.icQueue.find(x => x.uid === S.icSel) || items[0] || null;
  const top = list.scrollTop;
  list.innerHTML = H(items.length
    ? items.slice(0, 400).map(icItemHTML).join('')
    : '<div class="empty">Mudahale listesi bos.<br>Ustteki Request, Response veya WebSocket anahtarlarini actiginizda yakalanan tum trafik burada durdurulur ve iletildiginde listede kalir.</div>');
  list.scrollTop = top;
  if (force || sel) {
    det.innerHTML = H(sel ? icDetailHTML(sel) : '<div class="empty">Bir kayit sec.</div>');
  }
  const sp = $('#ic-split'); if (sp) sp.className = 'split ' + S.icView;
  const hs = sh.querySelector('.hist'); if (hs) hs.classList.toggle('dv', S.icView === 'detail');
}

/* ---------- REPEATER ---------- */
const rpCur = () => S.rp.tabs.find(t => t.id === S.rp.cur) || null;
function rpNew(from) {
  const t = { id: uid(), name: 'R' + (S.rp.tabs.length + 1), method: from ? from.method : 'GET', url: from ? from.url : '', headers: from ? hdrText(from.requestHeaders) : '', body: from ? from.requestBody : '', cred: 'same-origin', redirect: 'follow', resp: null, busy: false, rtab: 'pretty' };
  S.rp.tabs.push(t); S.rp.cur = t.id; return t;
}
function renderRepeater() {
  if (!S.rp.tabs.length) rpNew(selRec());
  const t = rpCur(), resp = t.resp;
  let respHTML = '';
  if (t.busy) respHTML = '<div class="empty">Gonderiliyor...</div>';
  else if (resp && resp.error) respHTML = `<pre>${esc(resp.error)}</pre><p class="hint">CORS veya ag hatasi olabilir.</p>`;
  else if (resp) respHTML = `<div class="row"><span class="st ${'s' + Math.floor(resp.status / 100)}">${resp.status}</span><span class="mut">${esc(resp.statusText)} · ${resp.ms} ms · ${fmtB(resp.size)}${resp.redirected ? ' · yonlendirildi' : ''}</span></div>
<div class="sub" style="padding:0">${[['pretty', 'Pretty'], ['raw', 'Raw'], ['hdr', 'Header'], ['render', 'Onizleme']].map(([k, l]) => `<button data-act="rp-rtab" data-k="${k}" class="${t.rtab === k ? 'on' : ''}">${l}</button>`).join('')}</div>
${t.rtab === 'render' ? `<iframe sandbox="" srcdoc="${esc(resp.body)}" style="width:100%;height:300px;border:1px solid var(--line);border-radius:8px;background:#fff;margin-top:8px"></iframe>` : `<pre class="tall" style="margin-top:8px">${esc(t.rtab === 'hdr' ? hdrText(resp.headers) : t.rtab === 'raw' ? limit(resp.body, 60000) : bodyView(resp.body))}</pre>`}
<div class="row"><button class="b sm" data-act="rp-copyres">${svgSym('copy')} Yaniti kopyala</button><button class="b sm" data-act="rp-tocmp">Karsilastir A</button><button class="b sm" data-act="rp-tocmpb">Karsilastir B</button></div>`;
  return `<div class="pad"><div class="chips">${S.rp.tabs.map(x => `<button class="b sm ${x.id === t.id ? 'on' : ''}" data-act="rp-tab" data-id="${x.id}">${esc(x.name)}</button>`).join('')}<button class="b sm" data-act="rp-add">${svgSym('plus')}</button><button class="b sm dng" data-act="rp-del">${svgSym('close')}</button></div>
<div class="row"><select data-b="rp.method" style="width:110px">${['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map(m => `<option ${t.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select><input class="grow" data-b="rp.url" value="${esc(t.url)}" placeholder="https://..."></div>
<label>Header</label><textarea data-b="rp.headers" placeholder="Content-Type: application/json">${esc(t.headers)}</textarea>
<label>Govde</label><textarea data-b="rp.body">${esc(t.body)}</textarea>
<div class="row"><select data-b="rp.cred" class="grow"><option value="same-origin" ${t.cred === 'same-origin' ? 'selected' : ''}>cerez: same-origin</option><option value="include" ${t.cred === 'include' ? 'selected' : ''}>cerez: include</option><option value="omit" ${t.cred === 'omit' ? 'selected' : ''}>cerez: yok</option></select><select data-b="rp.redirect" class="grow"><option value="follow" ${t.redirect === 'follow' ? 'selected' : ''}>yonlendirme: takip</option><option value="manual" ${t.redirect === 'manual' ? 'selected' : ''}>yonlendirme: manuel</option></select></div>
<div class="row"><button class="b pri" data-act="rp-send">${svgSym('play')} Gonder</button><button class="b" data-act="rp-load">Secili istegi yukle</button><button class="b" data-act="rp-dup">Cogalt</button><button class="b" data-act="rp-to-in">${svgSym('arrow')} Intruder</button></div>${respHTML}</div>`;
}
async function rpSend() {
  const t = rpCur(); if (!t || t.busy) return;
  t.busy = true; t.resp = null; renderTab();
  try { t.resp = await sendRaw({ method: t.method, url: t.url, headers: t.headers, body: t.body, cred: t.cred, redirect: t.redirect }, 'manual'); }
  catch (e) { t.resp = { error: String(e && e.message || e) }; }
  t.busy = false; if (S.open && S.tab === 'repeater') renderTab();
}

/* ---------- INTRUDER ---------- */
const PRESETS = {
  'Sayilar 1-100': () => Array.from({ length: 100 }, (_, i) => i + 1).join('\n'),
  'Yaygin yollar': () => ['admin', 'login', 'api', 'api/v1', 'config', 'backup', 'robots.txt', 'sitemap.xml', 'swagger.json', 'openapi.json', 'graphql', 'debug', 'test', 'dashboard', 'user', 'users', 'health', 'status', 'metrics'].join('\n'),
  'Sinir degerleri': () => ['0', '-1', '1', '99999999999', 'null', 'true', 'false', 'undefined', '[]', '{}'].join('\n'),
  'Bos / uzun': () => ['', ' ', 'A'.repeat(256), 'A'.repeat(4096)].join('\n')
};
function renderIntruder() {
  const T = S.in, res = T.results.slice();
  const lens = {}; res.forEach(r => { lens[r.len] = (lens[r.len] || 0) + 1; });
  const mode = +Object.keys(lens).sort((a, b) => lens[b] - lens[a])[0];
  const sorters = { n: (a, b) => a.n - b.n, status: (a, b) => String(a.status).localeCompare(String(b.status)), len: (a, b) => b.len - a.len, ms: (a, b) => b.ms - a.ms };
  res.sort(sorters[T.sort] || sorters.n);
  const sel = res.find(r => r.n === T.sel);
  return `<div class="pad"><p class="hint">Degistirilecek yerleri <b>§deger§</b> ile isaretle.</p>
<div class="row"><select data-b="in.method" style="width:110px">${['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map(m => `<option ${T.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select><input class="grow" data-b="in.url" value="${esc(T.url)}" placeholder="https://site/api/user/§1§"></div>
<label>Header</label><textarea data-b="in.headers">${esc(T.headers)}</textarea><label>Govde</label><textarea data-b="in.body">${esc(T.body)}</textarea>
<label>Payload listesi</label><textarea data-b="in.payloads" style="min-height:90px">${esc(T.payloads)}</textarea>
<div class="chips">${Object.keys(PRESETS).map(k => `<button class="b sm" data-act="in-preset" data-k="${esc(k)}">${esc(k)}</button>`).join('')}</div>
<div class="row"><select data-b="in.type" class="grow"><option value="sniper" ${T.type === 'sniper' ? 'selected' : ''}>Sniper</option><option value="ram" ${T.type === 'ram' ? 'selected' : ''}>Battering ram</option></select><input type="number" min="0" data-b="in.delay" value="${T.delay}" style="width:96px" placeholder="ms"><input type="number" min="1" max="6" data-b="in.conc" value="${T.conc}" style="width:80px"></div>
<div class="row"><button class="b ${T.running ? 'dng' : 'pri'}" data-act="in-run">${T.running ? 'Durdur' : 'Testi baslat'}</button><button class="b" data-act="in-clear">Sonuclari temizle</button><select data-b="in.sort" style="width:130px"><option value="n" ${T.sort === 'n' ? 'selected' : ''}>sira</option><option value="status" ${T.sort === 'status' ? 'selected' : ''}>durum</option><option value="len" ${T.sort === 'len' ? 'selected' : ''}>uzunluk</option><option value="ms" ${T.sort === 'ms' ? 'selected' : ''}>sure</option></select></div>
<div id="in-res">${res.length ? `<p class="hint">${res.length} sonuc · sari satir = en yaygin uzunluktan (${mode}) farkli</p><table><tr><th>#</th><th>Payload</th><th>Durum</th><th>Uzunluk</th><th>ms</th></tr>${res.slice(0, 600).map(r => `<tr class="${r.len !== mode ? 'odd' : ''} ${r.n === T.sel ? 'sel' : ''}" data-act="in-sel" data-i="${r.n}"><td>${r.n}</td><td>${esc(limit(r.payload, 60))}</td><td>${esc(r.status)}</td><td>${r.len}</td><td>${r.ms}</td></tr>`).join('')}</table>` : ''}</div>
${sel ? `<details open><summary>Yanit #${sel.n}</summary><pre class="tall">${esc(sel.error || limit(sel.body, 20000))}</pre></details>` : ''}</div>`;
}
async function runIntruder() {
  const T = S.in;
  if (T.running) { T.stop = true; return; }
  const joined = [T.url, T.headers, T.body].join('\u0000'), re = /§([\s\S]*?)§/g;
  const marks = [...joined.matchAll(re)];
  if (!marks.length) return toast('§ isareti yok');
  const pl = T.payloads.split(/\r?\n/);
  while (pl.length && pl[pl.length - 1] === '' && pl.length > 1) pl.pop();
  if (!T.payloads.length) return toast('Payload listesi bos');
  const jobs = [];
  if (T.type === 'ram') pl.forEach(p => jobs.push({ p, all: true }));
  else marks.forEach((_, i) => pl.forEach(p => jobs.push({ p, i })));
  if (jobs.length > 5000) return toast('En fazla 5000 istek');
  T.running = true; T.stop = false; T.results = []; renderTab();
  let n = 0, next = 0;
  const build = job => { let k = 0; const s = joined.replace(re, (m, d) => { const i = k++; return (job.all || job.i === i) ? job.p : d; }); const [u, h, b] = s.split('\u0000'); return { url: u, headers: h, body: b }; };
  const worker = async () => {
    while (!T.stop && next < jobs.length) {
      const job = jobs[next++], my = ++n, t0 = performance.now(); const o = build(job);
      try {
        const r = await sendRaw({ method: T.method, url: o.url, headers: o.headers, body: o.body, cred: 'same-origin' }, 'intruder');
        T.results.push({ n: my, payload: job.p, status: r.status, len: r.size, ms: r.ms, body: r.body });
      } catch (e) { T.results.push({ n: my, payload: job.p, status: 'ERR', len: 0, ms: Math.round(performance.now() - t0), error: String(e.message || e) }); }
      if (S.open && S.tab === 'intruder' && my % 3 === 0) liveIntruder();
      if (T.delay > 0) await new Promise(r => setTimeout(r, T.delay));
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(6, +T.conc || 1)) }, worker));
  T.running = false; if (S.open && S.tab === 'intruder') renderTab(); toast('Intruder bitti: ' + T.results.length + ' istek');
}
function liveIntruder() { const y = bodyEl.scrollTop; renderTab(); bodyEl.scrollTop = y; }

/* ---------- DECODER ---------- */
const b64d = s => { s = s.trim().replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const bin = atob(s); try { return decodeURIComponent(escape(bin)); } catch (e) { return bin; } };
const hexs = s => [...new TextEncoder().encode(s)].map(b => b.toString(16).padStart(2, '0')).join('');
const dig = async (alg, s) => [...new Uint8Array(await crypto.subtle.digest(alg, new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
const DEC = {
  'Akilli coz': s => {
    const t = s.trim();
    if (/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(t)) return DEC['JWT coz'](t);
    if (/%[0-9a-f]{2}/i.test(t)) return decodeURIComponent(t);
    if (/^([0-9a-f]{2})+$/i.test(t) && t.length % 2 === 0) return DEC['Hex coz'](t);
    if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(t) && t.length >= 8) return b64d(t);
    if (/\\u[0-9a-f]{4}/i.test(t)) return DEC['Unicode coz'](t);
    if (/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(t)) return DEC['HTML coz'](t);
    if (/^\d{10,13}$/.test(t)) return DEC['Zaman damgasi -> tarih'](t);
    return 'Bicim taninamadi';
  },
  'URL kodla': s => encodeURIComponent(s), 'URL coz': s => decodeURIComponent(s),
  'Base64 kodla': s => btoa(unescape(encodeURIComponent(s))), 'Base64 coz': s => b64d(s),
  'HTML kodla': s => esc(s), 'HTML coz': s => new DOMParser().parseFromString(s, 'text/html').documentElement.textContent,
  'Hex kodla': s => hexs(s), 'Hex coz': s => new TextDecoder().decode(new Uint8Array(s.replace(/[^0-9a-f]/gi, '').match(/../g).map(h => parseInt(h, 16)))),
  'Unicode kacis': s => [...s].map(c => c.charCodeAt(0) > 127 ? '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0') : c).join(''),
  'Unicode coz': s => s.replace(/\\u([0-9a-f]{4})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))),
  'JSON guzellestir': s => JSON.stringify(JSON.parse(s), null, 2), 'JSON sikistir': s => JSON.stringify(JSON.parse(s)),
  'JWT coz': s => jwtDecode(s.trim()),
  'Zaman damgasi -> tarih': s => { const n = Number(s.trim()); return new Date(n > 1e11 ? n : n * 1000).toISOString(); },
  'Tarih -> zaman damgasi': s => String(Math.floor(Date.parse(s) / 1000)),
  'Ters cevir': s => [...s].reverse().join(''), 'ROT13': s => s.replace(/[a-z]/gi, c => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b); }),
  'Query -> JSON': s => JSON.stringify(Object.fromEntries(new URLSearchParams(s.replace(/^[^?]*\?/, ''))), null, 2),
  'SHA-1': s => dig('SHA-1', s), 'SHA-256': s => dig('SHA-256', s), 'SHA-384': s => dig('SHA-384', s), 'SHA-512': s => dig('SHA-512', s)
};
function renderDecoder() {
  return `<div class="pad"><label>Giris</label><textarea class="wrap" data-b="dec.inp" style="min-height:110px">${esc(S.dec.inp)}</textarea>
<div class="row"><select class="grow" data-b="dec.op">${Object.keys(DEC).map(k => `<option ${k === S.dec.op ? 'selected' : ''}>${esc(k)}</option>`).join('')}</select><button class="b pri" data-act="dec-run">Uygula</button></div>
<label>Cikti</label><textarea class="wrap" id="dec-out" readonly style="min-height:110px">${esc(S.dec.out)}</textarea>
<div class="row"><button class="b" data-act="dec-move">Ciktiyi girise tasi</button><button class="b" data-act="dec-copy">${svgSym('copy')} Kopyala</button><button class="b" data-act="dec-cmp">Karsilastir A</button></div></div>`;
}
async function decRun() {
  try { S.dec.out = String(await DEC[S.dec.op](S.dec.inp)); } catch (e) { S.dec.out = 'Hata: ' + e.message; }
  const o = $('#dec-out'); if (o) o.value = S.dec.out;
}

/* ---------- KARSILASTIR ---------- */
function diffSeq(a, b) {
  const n = a.length, m = b.length, w = m + 1, dp = new Uint16Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i * w + j] = a[i] === b[j] ? dp[(i + 1) * w + j + 1] + 1 : Math.max(dp[(i + 1) * w + j], dp[i * w + j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) { if (a[i] === b[j]) { out.push(['=', a[i]]); i++; j++; } else if (dp[(i + 1) * w + j] >= dp[i * w + j + 1]) out.push(['-', a[i++]]); else out.push(['+', b[j++]]); }
  while (i < n) out.push(['-', a[i++]]); while (j < m) out.push(['+', b[j++]]);
  return out;
}
function renderCompare() {
  return `<div class="pad"><label>A ${esc(S.cmp.la)}</label><textarea data-b="cmp.a" style="min-height:90px">${esc(S.cmp.a)}</textarea>
<label>B ${esc(S.cmp.lb)}</label><textarea data-b="cmp.b" style="min-height:90px">${esc(S.cmp.b)}</textarea>
<div class="row"><select data-b="cmp.mode" style="width:130px"><option value="line" ${S.cmp.mode === 'line' ? 'selected' : ''}>Satir</option><option value="word" ${S.cmp.mode === 'word' ? 'selected' : ''}>Kelime</option></select><button class="b pri" data-act="cmp-run">Karsilastir</button><button class="b" data-act="cmp-swap">A &lt;-&gt; B</button></div>
<div id="cmp-out"></div></div>`;
}
function cmpRun() {
  const out = $('#cmp-out'); if (!out) return;
  const word = S.cmp.mode === 'word', split = t => word ? t.split(/(\s+)/) : t.split('\n');
  const a = split(S.cmp.a), b = split(S.cmp.b);
  if (a.length > 2500 || b.length > 2500) { out.innerHTML = H('<p class="hint">Cok buyuk (en fazla 2500 parca).</p>'); return; }
  const d = diffSeq(a, b), add = d.filter(x => x[0] === '+').length, del = d.filter(x => x[0] === '-').length;
  out.innerHTML = H(`<p class="hint"><ins>+${add}</ins> eklendi · <del>-${del}</del> silindi</p><div class="diff">${word ? d.map(([t, v]) => t === '=' ? esc(v) : t === '+' ? `<ins>${esc(v)}</ins>` : `<del>${esc(v)}</del>`).join('') : d.map(([t, v]) => `<span class="ln ${t === '+' ? 'a' : t === '-' ? 'd' : ''}">${t === '+' ? '+ ' : t === '-' ? '- ' : '  '}${esc(v)}</span>`).join('')}</div>`);
}

/* ---------- HEDEF ---------- */
function renderTarget() {
  const hosts = {};
  S.requests.forEach(r => { let u; try { u = new URL(r.url); } catch (e) { return; } const h = hosts[u.host] = hosts[u.host] || { n: 0, paths: {} }; h.n++; const p = h.paths[u.pathname] = h.paths[u.pathname] || { n: 0, m: new Set(), s: new Set() }; p.n++; p.m.add(r.method); p.s.add(r.status); });
  const keys = Object.keys(hosts).sort((a, b) => hosts[b].n - hosts[a].n);
  if (!keys.length) return '<div class="empty">Henuz hedef yok.</div>';
  return `<div class="pad">${keys.map(h => `<details ${keys.length < 4 ? 'open' : ''}><summary>${esc(h)} <small>${hosts[h].n}</small></summary><div><div class="row"><button class="b sm" data-act="tg-host" data-k="${esc(h)}">Bu host'u filtrele</button></div><table>${Object.keys(hosts[h].paths).sort().slice(0, 300).map(p => { const o = hosts[h].paths[p]; return `<tr data-act="tg-path" data-h="${esc(h)}" data-k="${esc(p)}"><td>${esc(p)}</td><td>${[...o.m].join(',')}</td><td>${[...o.s].join(',')}</td><td>${o.n}</td></tr>`; }).join('')}</table></div></details>`).join('')}</div>`;
}

/* ---------- SAYFA ARACLARI ---------- */
const PG = [['cookies', 'Cerez'], ['storage', 'Depolama'], ['forms', 'Form'], ['links', 'Endpoint'], ['secrets', 'Sirlar'], ['console', 'Konsol'], ['dom', 'Oge'], ['info', 'Bilgi'], ['source', 'Kaynak']];
S._res = {}; S._nc = { k: '', v: '' }; S._ns = { area: 'localStorage', k: '', v: '' };
function renderPage() {
  const nav = `<div class="sub">${PG.map(([k, l]) => `<button data-act="pg" data-k="${k}" class="${S.pg === k ? 'on' : ''}">${l}</button>`).join('')}</div>`;
  return nav + '<div class="pad">' + ({ cookies: pgCookies, storage: pgStorage, forms: pgForms, links: pgLinks, secrets: pgSecrets, console: pgConsole, dom: pgDom, info: pgInfo, source: pgSource }[S.pg])() + '</div>';
}
function pageAfter() { if (S.pg === 'console') consRefresh(); }
const ckList = () => D.cookie ? D.cookie.split(/;\s*/).map(s => { const i = s.indexOf('='); return { k: i < 0 ? s : s.slice(0, i), v: i < 0 ? '' : s.slice(i + 1) }; }) : [];
function pgCookies() {
  const l = ckList();
  return `<p class="hint">Yalnizca JavaScript'in gorebildigi cerezler (HttpOnly haric).</p>
${l.map((c, i) => `<label>${esc(c.k)}</label><div class="row"><input class="grow" data-ckv="${i}" value="${esc(c.v)}"><button class="b sm" data-act="ck-save" data-i="${i}">Kaydet</button><button class="b sm dng" data-act="ck-del" data-i="${i}">Sil</button></div>`).join('') || '<div class="empty">Cerez yok.</div>'}
<label>Yeni cerez</label><div class="row"><input class="grow" data-b="nc.k" placeholder="ad" value="${esc(S._nc.k)}"><input class="grow" data-b="nc.v" placeholder="deger" value="${esc(S._nc.v)}"><button class="b sm pri" data-act="ck-add">Ekle</button></div>
<div class="row"><button class="b sm" data-act="ck-copy">Hepsini kopyala</button><button class="b sm dng" data-act="ck-clear">Hepsini sil</button></div>`;
}
const stList = () => { const o = []; ['localStorage', 'sessionStorage'].forEach(a => { try { const s = W[a]; for (let i = 0; i < s.length; i++) { const k = s.key(i); if (k.indexOf('ip5:') === 0) continue; o.push({ a, k, v: s.getItem(k) }); } } catch (e) {} }); return o; };
function pgStorage() {
  const l = stList(); S._st = l;
  return `${l.map((c, i) => `<label>${c.a === 'localStorage' ? 'local' : 'session'} · ${esc(c.k)}</label><textarea class="wrap" data-stv="${i}" style="min-height:48px">${esc(limit(c.v, 20000))}</textarea><div class="row"><button class="b sm" data-act="st-save" data-i="${i}">Kaydet</button><button class="b sm dng" data-act="st-del" data-i="${i}">Sil</button><button class="b sm" data-act="st-copy" data-i="${i}">Kopyala</button></div>`).join('') || '<div class="empty">Depolama bos.</div>'}
<label>Yeni kayit</label><div class="row"><select data-b="ns.area" style="width:120px"><option>localStorage</option><option>sessionStorage</option></select><input class="grow" data-b="ns.k" placeholder="anahtar" value="${esc(S._ns.k)}"></div><textarea data-b="ns.v" placeholder="deger">${esc(S._ns.v)}</textarea><div class="row"><button class="b sm pri" data-act="st-add">Ekle</button></div>`;
}
function pgForms() {
  const fs = [...D.forms];
  return `<div class="row"><button class="b sm pri" data-act="fm-unlock">Kilitleri ac (gizli/disabled/readonly/maxlength)</button></div>
${fs.map(f => `<details><summary>${esc((f.method || 'get').toUpperCase())} ${esc(f.getAttribute('action') || '(ayni sayfa)')} <small>${f.elements.length} alan</small></summary><div><table>${[...f.elements].filter(e => e.name || e.id).map(e => `<tr><td>${esc(e.name || e.id)}</td><td>${esc(e.type || e.tagName)}</td><td>${esc(limit(e.type === 'password' ? '****' : e.value, 80))}</td></tr>`).join('')}</table></div></details>`).join('') || '<div class="empty">Sayfada form yok.</div>'}`;
}
async function corpus() {
  if (S._corp) return S._corp;
  const html = D.documentElement.outerHTML; let txt = html; const srcs = [];
  const scripts = [...D.scripts].filter(s => s.src).slice(0, 30);
  await Promise.all(scripts.map(async s => { try { const r = await nativeFetch(s.src, { credentials: 'omit' }); const t = (await r.text()).slice(0, 1500000); srcs.push(s.src); txt += '\n' + t; } catch (e) {} }));
  return (S._corp = { text: txt, n: srcs.length });
}
async function scanLinks() {
  S._corp = null; toast('Taraniyor...');
  const c = await corpus(); const urls = new Set(), paths = new Set(), params = new Set();
  (c.text.match(/https?:\/\/[^\s"'`<>\\)]{4,}/g) || []).forEach(u => urls.add(u.replace(/[,;]+$/, '')));
  let m; const re = /["'`](\/(?!\/)[A-Za-z0-9_\-.\/~%]{2,}(?:\?[A-Za-z0-9_\-.=&%[\]]*)?)["'`]/g;
  while ((m = re.exec(c.text))) paths.add(m[1]);
  [...urls, ...paths].forEach(u => { const q = u.split('?')[1]; if (q) q.split('&').forEach(p => params.add(p.split('=')[0])); });
  [...D.querySelectorAll('input[name],select[name],textarea[name]')].forEach(e => params.add(e.name));
  S._res.links = { urls: [...urls].sort(), paths: [...paths].sort(), params: [...params].sort(), n: c.n }; renderTab();
}
function pgLinks() {
  const r = S._res.links;
  const blk = (t, a) => `<details open><summary>${t} <small>${a.length}</small></summary><div><div class="row"><button class="b sm" data-act="copy-list" data-k="${t}">Kopyala</button></div><pre class="tall">${esc(a.slice(0, 800).join('\n'))}</pre></div></details>`;
  return `<div class="row"><button class="b pri" data-act="scan-links">${r ? 'Yeniden tara' : 'Tara'}</button><span class="mut">DOM + satir ici ve harici JS dosyalari</span></div>${r ? blk('Yollar', r.paths) + blk('URL\'ler', r.urls) + blk('Parametreler', r.params) : ''}`;
}
const SECRETS = [['AWS erisim anahtari', /AKIA[0-9A-Z]{16}/g], ['Google API anahtari', /AIza[0-9A-Za-z_-]{35}/g], ['Stripe anahtari', /[sr]k_live_[0-9a-zA-Z]{20,}/g], ['Slack token', /xox[baprs]-[0-9A-Za-z-]{10,}/g], ['GitHub token', /gh[pousr]_[A-Za-z0-9]{36,}/g], ['JWT', /eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*/g], ['Ozel anahtar', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g], ['Genel sir', /(?:api[_-]?key|secret|token|passw(?:or)?d|client[_-]?secret)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/gi], ['E-posta', /[\w.+-]+@[\w-]+\.[\w.-]{2,}/g], ['Ic IP', /\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/g]];
async function scanSecrets() {
  S._corp = null; toast('Taraniyor...'); const c = await corpus(); const out = [];
  SECRETS.forEach(([n, re]) => { const s = new Set(c.text.match(re) || []); s.forEach(v => out.push([n, v])); });
  S._res.secrets = out; renderTab();
}
const maskv = v => (S.set.mask && !/^eyJ/.test(v) && v.length > 16) ? v.slice(0, 8) + '...' + v.slice(-4) : v;
function pgSecrets() {
  const r = S._res.secrets;
  return `<div class="row"><button class="b pri" data-act="scan-secrets">${r ? 'Yeniden tara' : 'Tara'}</button><span class="mut">Sayfa ve JS dosyalarinda anahtar/token desenleri</span></div>${r ? (r.length ? `<table>${r.slice(0, 300).map(([n, v]) => `<tr><td>${esc(n)}</td><td>${esc(limit(maskv(v), 120))}</td></tr>`).join('')}</table>` : '<div class="empty">Bir sey bulunamadi.</div>') : ''}`;
}
function pgConsole() {
  return `<div id="cons-log" style="max-height:34vh;overflow:auto;margin-bottom:8px"></div><textarea class="wrap" data-b="cons.code" id="cons-code" placeholder="JavaScript... (await destekli, $0 = secili oge)" style="min-height:64px"></textarea><div class="row"><button class="b pri" data-act="cons-run">${svgSym('play')} Calistir</button><button class="b" data-act="cons-clear">Temizle</button></div>`;
}
function consRefresh() { const l = $('#cons-log'); if (!l) return; l.innerHTML = H(S.cons.slice(-120).map(c => `<div class="cl ${c.lvl}"><span class="mut">${new Date(c.time).toLocaleTimeString()}</span><span>${esc(c.t)}</span></div>`).join('') || '<div class="empty">Konsol ciktisi yok.</div>'); l.scrollTop = l.scrollHeight; }
async function consRun() {
  const ta = $('#cons-code'); const code = ta.value.trim(); if (!code) return;
  consPush('info', ['> ' + code]); W.$0 = S.picked;
  try { let r; try { r = await (0, eval)('(async()=>(' + code + '))()'); } catch (e) { if (e instanceof SyntaxError) r = await (0, eval)('(async()=>{' + code + '})()'); else throw e; }
    consPush('log', [r === undefined ? 'undefined' : (r instanceof Node ? '<' + r.nodeName.toLowerCase() + '>' : typeof r === 'function' ? String(r) : safe(r))]);
  } catch (e) { consPush('error', [String(e)]); }
}
const cssPath = el => { const p = []; while (el && el.nodeType === 1 && el !== D.documentElement) { let s = el.nodeName.toLowerCase(); if (el.id) { p.unshift(s + '#' + CSS_esc(el.id)); break; } const sib = el.parentNode ? [...el.parentNode.children].filter(x => x.nodeName === el.nodeName) : []; if (sib.length > 1) s += ':nth-of-type(' + (sib.indexOf(el) + 1) + ')'; p.unshift(s); el = el.parentNode; } return p.join(' > '); };
const CSS_esc = s => (W.CSS && CSS.escape) ? CSS.escape(s) : s;
function pgDom() {
  const e = S.picked;
  return `<div class="row"><button class="b pri" data-act="pick">Oge sec (ekrana dokun)</button><span class="mut">Panel kapanir; bir ogeye dokun.</span></div>${e ? `<label>Secici</label><pre>${esc(cssPath(e))}</pre><label>Oznitelikler</label><pre>${esc([...e.attributes].map(a => a.name + '="' + a.value + '"').join('\n') || '(yok)')}</pre><label>outerHTML (duzenle)</label><textarea class="wrap" id="dom-html" style="min-height:120px">${esc(limit(e.outerHTML, 30000))}</textarea><div class="row"><button class="b sm pri" data-act="dom-apply">Uygula</button><button class="b sm" data-act="dom-copy">HTML kopyala</button><button class="b sm" data-act="dom-sel">Secici kopyala</button><button class="b sm" data-act="dom-hide">Gizle</button><button class="b sm dng" data-act="dom-del">Sil</button><button class="b sm" data-act="dom-parent">Ust oge ${svgSym('up')}</button></div><p class="hint">Konsolda $0 bu ogedir.</p>` : ''}`;
}
let picking = false;
function startPick() {
  picking = true; closePanel(); toast('Bir ogeye dokun');
  const hl = $('#hl'), skip = e => e.composedPath().includes(host);
  const move = e => { if (skip(e)) return; const r = e.target.getBoundingClientRect(); Object.assign(hl.style, { display: 'block', left: r.left + 'px', top: r.top + 'px', width: r.width + 'px', height: r.height + 'px' }); };
  const block = e => { if (skip(e)) return; e.preventDefault(); e.stopPropagation(); };
  const done = e => { if (skip(e)) return; block(e); S.picked = e.target; W.$0 = e.target; stop(); S.tab = 'page'; S.pg = 'dom'; openPanel(); };
  const stop = () => { picking = false; hl.style.display = 'none'; ['pointerover', 'touchstart'].forEach(t => D.removeEventListener(t, move, true)); ['pointerdown', 'mousedown', 'mouseup', 'touchend'].forEach(t => D.removeEventListener(t, block, true)); D.removeEventListener('click', done, true); };
  ['pointerover', 'touchstart'].forEach(t => D.addEventListener(t, move, true)); ['pointerdown', 'mousedown', 'mouseup', 'touchend'].forEach(t => D.addEventListener(t, block, true)); D.addEventListener('click', done, true);
}
function pgInfo() {
  const fw = []; [['React', !!(W.React || D.querySelector('[data-reactroot]'))], ['Vue', !!(W.Vue || W.__VUE__)], ['Angular', !!(W.ng || D.querySelector('[ng-version]'))], ['jQuery', !!W.jQuery], ['Next.js', !!W.__NEXT_DATA__], ['Nuxt', !!W.__NUXT__], ['Svelte', !!D.querySelector('[class*=svelte-]')]].forEach(([n, ok]) => ok && fw.push(n));
  const rows = [['URL', location.href], ['Baslik', D.title], ['Cerez erisimi', navigator.cookieEnabled ? 'acik' : 'kapali'], ['Cerez sayisi', ckList().length], ['Cerceveler', fw.join(', ') || '-'], ['iframe', D.querySelectorAll('iframe').length], ['Script', D.scripts.length], ['Ekran', W.innerWidth + 'x' + W.innerHeight + ' @' + W.devicePixelRatio], ['Baglanti', navigator.connection ? navigator.connection.effectiveType : '-'], ['Dil', navigator.language], ['Guvenli baglam', W.isSecureContext], ['UA', navigator.userAgent]];
  const sh2 = S._res.sec;
  return `<table>${rows.map(([k, v]) => `<tr><td>${k}</td><td>${esc(v)}</td></tr>`).join('')}</table>
<div class="row"><button class="b pri" data-act="scan-sec">Guvenlik basliklarini denetle</button></div>${sh2 ? `<table>${sh2.map(([k, v, ok]) => `<tr><td>${esc(k)}</td><td>${ok ? 'OK' : 'YOK'}</td><td>${esc(limit(v || 'yok', 140))}</td></tr>`).join('')}</table>` : ''}`;
}
async function scanSec() {
  try {
    const r = await nativeFetch(location.href, { cache: 'no-store', credentials: 'same-origin' }); const h = r.headers;
    S._res.sec = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'cross-origin-embedder-policy'].map(k => [k, h.get(k), !!h.get(k)]);
    S._res.sec.push(['server', h.get('server'), true], ['x-powered-by', h.get('x-powered-by'), !h.get('x-powered-by')]);
  } catch (e) { S._res.sec = [['hata', String(e), false]]; }
  renderTab();
}
function pgSource() { return `<div class="row"><input class="grow" id="src-q" placeholder="ara..."><button class="b" data-act="src-find">Bul</button><button class="b" data-act="src-copy">Kopyala</button></div><textarea id="src-t" readonly style="min-height:50vh">${esc(limit(D.documentElement.outerHTML, 400000))}</textarea>`; }

/* ---------- KURALLAR (MATCH & REPLACE) ---------- */
S._nr = { target: 'req-header', match: '', replace: '', regex: false };
function renderRules() {
  const T = { 'req-url': 'Istek URL', 'req-header': 'Istek header', 'req-body': 'Istek govde', 'res-body': 'Yanit govde (fetch)' };
  return `<div class="pad"><h4 style="margin:0 0 4px">Match &amp; Replace</h4><p class="hint">Istek giderken veya yanit donerken otomatik degistirir.</p>
${S.rules.map((r, i) => `<div class="row"><label class="ck grow" style="margin:0"><input type="checkbox" data-act="rule-on" data-i="${i}" ${r.on ? 'checked' : ''}><span>${esc(T[r.target])}: <code>${esc(limit(r.match, 40))}</code> -&gt; <code>${esc(limit(r.replace, 40))}</code>${r.regex ? ' (regex)' : ''}</span></label><button class="b sm dng" data-act="rule-del" data-i="${i}">Sil</button></div>`).join('') || '<div class="empty">Kural yok.</div>'}
<label>Yeni kural</label><select data-b="nr.target">${Object.keys(T).map(k => `<option value="${k}" ${S._nr.target === k ? 'selected' : ''}>${T[k]}</option>`).join('')}</select>
<input data-b="nr.match" placeholder="Aranan" value="${esc(S._nr.match)}" style="margin-top:6px"><input data-b="nr.replace" placeholder="Yerine" value="${esc(S._nr.replace)}" style="margin-top:6px">
<label class="ck"><input type="checkbox" data-b="nr.regex" ${S._nr.regex ? 'checked' : ''}>Regex</label><div class="row"><button class="b pri" data-act="rule-add">Kural ekle</button></div></div>`;
}

/* ---------- EK SCRIPT (JS YAZMA, OTOMATIK HOOK VE ANLIK CALISTIRMA) ---------- */
const SCRIPT_TEMPLATES = {
  'Bearer Token Bul': 'const found = [];\n__inspectorPro.state.requests.forEach(r => {\n  const h = JSON.stringify(r.requestHeaders || {});\n  const m = h.match(/Bearer\\s+[A-Za-z0-9\\-._~+/]+=*/i);\n  if (m) found.push({ url: r.url, token: m[0] });\n});\nreturn found;',
  'Form Kilitlerini Ac': 'let n = 0;\ndocument.querySelectorAll("input[type=hidden]").forEach(el => { el.type = "text"; el.style.outline = "2px solid #ff8a3d"; n++; });\ndocument.querySelectorAll("[disabled],[readonly]").forEach(el => { el.removeAttribute("disabled"); el.removeAttribute("readonly"); n++; });\nreturn n + " form alani acildi";',
  'Tum Endpointleri Listele': 'return [...new Set(__inspectorPro.state.requests.map(r => r.method + " " + r.url))];',
  'Ozel Header Ekle (Before)': '// Before Request kutusuna yapisitirin:\nrequest.headers["X-Debug-Inspector"] = "true";'
};

function renderScripts() {
  return `<div class="pad">
  <div class="card">
    <h4>${svgSym('code')} Ek Script — Anlik JavaScript Calistirici</h4>
    <p class="hint">Sayfa icinde dogrudan JavaScript yazip calistirabilirsiniz. <code>__inspectorPro</code>, <code>window</code>, <code>document</code> ve <code>$0</code> degiskenlerine erisilebilir (<code>await</code> desteklenir).</p>
    <div class="chips">${Object.keys(SCRIPT_TEMPLATES).map(k => `<button class="b sm" data-act="sc-tpl" data-k="${esc(k)}">${esc(k)}</button>`).join('')}</div>
    <textarea data-b="sc.custom" id="sc-custom-ta" style="min-height:130px" placeholder="// JavaScript kodunuzu buraya yazin...">${esc(S.scripts.custom || '')}</textarea>
    <div class="row">
      <button class="b pri" data-act="sc-run-custom">${svgSym('play')} Scripti Calistir</button>
      <button class="b" data-act="sc-clear-logs">Ciktiyi Temizle</button>
    </div>
    <label>Calistirma Ciktisi</label>
    <pre style="min-height:80px;max-height:200px">${esc(S.scriptLogs.join('\n\n') || '(Henuz cikti yok)')}</pre>
  </div>
  <div class="card">
    <h4>${svgSym('sliders')} Trafik Hook Betikleri (Otomatik Calisir)</h4>
    <p class="hint"><code>Before Request</code> her istek cikmadan once, <code>After Response</code> ise yanit donerken otomatik calisir.</p>
    <label>Before Request (<code>request.method</code>, <code>request.url</code>, <code>request.headers</code>, <code>request.body</code>)</label>
    <textarea data-b="sc.before" style="min-height:90px" placeholder="request.headers['X-Custom-Header'] = '1';">${esc(S.scripts.before || '')}</textarea>
    <label>After Response (<code>response.status</code>, <code>response.headers</code>, <code>response.body</code>)</label>
    <textarea data-b="sc.after" style="min-height:90px" placeholder="response.body = response.body.replace('false', 'true');">${esc(S.scripts.after || '')}</textarea>
  </div>
</div>`;
}

async function runCustomScript() {
  const code = (S.scripts.custom || '').trim();
  if (!code) return toast('Calistirilacak script bos');
  W.$0 = S.picked;
  try {
    let res;
    try {
      res = await (0, eval)('(async()=>{\n' + code + '\n})()');
    } catch (e) {
      if (e instanceof SyntaxError) res = await (0, eval)('(async()=>(' + code + '))()');
      else throw e;
    }
    const stamp = new Date().toLocaleTimeString();
    S.scriptLogs.unshift(`[${stamp}] Sonuc:\n` + (res === undefined ? 'undefined (Tamamlandi)' : safe(res)));
    if (S.scriptLogs.length > 30) S.scriptLogs.pop();
    toast('Script calistirildi');
  } catch (e) {
    const stamp = new Date().toLocaleTimeString();
    S.scriptLogs.unshift(`[${stamp}] HATA:\n` + (e && e.stack ? e.stack : String(e)));
    toast('Script hatasi');
  }
  if (S.open && S.tab === 'scripts') renderTab();
}

/* ---------- KULLANIM KILAVUZU ---------- */
function renderGuide() {
  return `<div class="pad">
<div class="card"><h4>1. Istekler ve HAR / Bearer Ozellikleri</h4><p class="hint"><code>Istekler</code> sekmesi sayfadaki tum <code>fetch</code>, <code>XHR</code>, <code>WebSocket</code>, <code>SSE</code>, <code>sendBeacon</code> ve kaynak trafigini yakalar. Header veya govdede <b>Bearer token</b> varsa asla gizlenmez, acikca gosterilir ve tek tusla kopyalanir. Kopyala menusunden <b>HAR Kopyala</b> secenegiyle istek + yaniti HAR 1.2 formatinda panoya alabilirsiniz.</p></div>
<div class="card"><h4>2. Mudahale (Eszamanli Request + Response + WebSocket Intercept)</h4><p class="hint"><code>Mudahale</code> sekmesindeki <b>Request Inspect</b>, <b>Response Inspect</b>, <b>WS Giden</b> ve <b>WS Gelen</b> anahtarlarinin hepsi ayni anda acik kullanilabilir. Request Inspect ile yakaladiginiz bir istegi duzenleyip <b>Ilet</b> dediginizde istek listeden silinmez; yaniti geldiginde Response Inspect aciksa yanit da durdurulur ve duzenleyip ilettikten sonra sayfaya ulasir.</p></div>
<div class="card"><h4>3. Repeater, Intruder, Decoder ve Karsilastir</h4><p class="hint"><b>Repeater</b> ile istekleri tekrar gonderebilir, <b>Intruder</b> ile <code>§deger§</code> isaretli parametrelere otomatik test listeleri uygulayabilirsiniz. <b>Decoder</b> Base64, URL, Hex, JWT ve hash donusumleri yapar; <b>Karsilastir</b> iki yaniti satir veya kelime bazinda kiyaslar.</p></div>
<div class="card"><h4>4. Kurallar ve Ek Script</h4><p class="hint"><b>Kurallar</b> sekmesi otomatik <code>Match &amp; Replace</code> tanimlar. <b>Ek Script</b> sekmesinden ise sayfada anlik JavaScript calistirabilir veya trafik akisina otomatik <code>Before Request / After Response</code> betikleri baglayabilirsiniz.</p></div>
<div class="card"><h4>5. Menu Boyutu ve Kisayollar</h4><p class="hint"><b>Ayarlar</b> sekmesinden menu genislik ve yuksekligini piksel olarak veya hazir sablonlarla ayarlayabilir, sag alt koseden surukleyerek boyutlandirabilirsiniz. Kisayol: <code>Alt + Shift + I</code> paneli acar/kapatir.</p></div>
</div>`;
}

/* ---------- AYARLAR ---------- */
function renderSettings() {
  const s = S.set;
  return `<div class="pad">
<label class="ck"><input type="checkbox" data-b="set.showBearer" ${s.showBearer !== false ? 'checked' : ''}>Bearer tokenlari her zaman acik goster (Maskeleme)</label>
<label class="ck"><input type="checkbox" data-b="set.mask" ${s.mask ? 'checked' : ''}>Diger hassas header'lari maskele (Cookie/Password vb.)</label>
<label class="ck"><input type="checkbox" data-b="set.bodies" ${s.bodies ? 'checked' : ''}>Istek / yanit govdesini yakala</label>
<label class="ck"><input type="checkbox" data-b="set.pretty" ${s.pretty ? 'checked' : ''}>JSON'u guzellestir</label>
<label class="ck"><input type="checkbox" data-b="set.outside" ${s.outside ? 'checked' : ''}>Panel disina tiklaninca otomatik kucult</label>
${EXT ? `<label class="ck"><input type="checkbox" data-b="set.persist" ${s.persist ? 'checked' : ''}>Sayfa gezinirken kayitlari sakla</label><label class="ck"><input type="checkbox" data-b="set.startOpen" ${s.startOpen ? 'checked' : ''}>Sayfa acilinca paneli otomatik ac</label>` : ''}
<label>Menu Boyut Sablonu</label>
<select data-b="set.panelSizePreset">
  <option value="compact" ${s.panelSizePreset === 'compact' ? 'selected' : ''}>Kompakt (440x520)</option>
  <option value="standard" ${s.panelSizePreset === 'standard' ? 'selected' : ''}>Standart (680x720)</option>
  <option value="wide" ${s.panelSizePreset === 'wide' ? 'selected' : ''}>Genis (920x780)</option>
  <option value="custom" ${s.panelSizePreset === 'custom' ? 'selected' : ''}>Ozel Boyut</option>
</select>
<div class="row">
  <div class="grow"><label>Genislik (px)</label><input type="number" min="340" max="1800" data-b="set.panelW" value="${s.panelW}"></div>
  <div class="grow"><label>Yukseklik (px)</label><input type="number" min="300" max="1300" data-b="set.panelH" value="${s.panelH}"></div>
</div>
<label>Tema</label><select data-b="set.theme">${[['auto', 'Otomatik'], ['dark', 'Koyu'], ['light', 'Acik']].map(([k, l]) => `<option value="${k}" ${s.theme === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
<label>Yazi boyutu (px)</label><input type="number" min="10" max="20" data-b="set.font" value="${s.font}">
<label>Maksimum kayit</label><input type="number" min="50" max="5000" data-b="set.max" value="${s.max}">
<label>Mudahalede otomatik ilet (sn, 0 = sinirsiz bekle)</label><input type="number" min="0" max="600" data-b="set.icTimeout" value="${s.icTimeout}">
<h4 style="margin:16px 0 4px">Canli dashboard (ayri sekme)</h4><div class="row"><button class="b ${S.tabMode ? 'on' : ''}" data-act="tabmode">Sekme modu: ${S.tabMode ? 'ACIK' : 'KAPALI'}</button><button class="b" data-act="opentab">Dashboard ac</button></div>
<div class="row" style="margin-top:14px"><button class="b" data-act="clear">Kayitlari temizle</button><button class="b dng" data-act="destroy">Inspector'i kaldir</button></div>
<p class="hint">Inspector Pro ${VER}${EXT ? ' · Eklenti Modu' : ' · Yer Imi Modu'}</p></div>`;
}

/* ---------- DASHBOARD ---------- */
function dashMain(CH) {
  const ch = new BroadcastChannel(CH), app = document.getElementById('app'), con = document.getElementById('connection');
  let data = { requests: [] }, selected = null, page = 'traffic', q = '';
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const hdr = o => Object.entries(o || {}).map(([k, v]) => k + ': ' + v).join('\n');
  function render() {
    const all = data.requests || [], reqs = q ? all.filter(r => (r.method + ' ' + r.status + ' ' + r.url).toLowerCase().includes(q)) : all;
    const cur = all.find(r => r.id === selected) || all.find(r => r.id === data.selected) || all[0];
    if (!selected && cur) selected = cur.id;
    app.innerHTML = `<nav>${['traffic', 'repeater', 'status'].map(k => `<button data-tab="${k}" class="${page === k ? 'active' : ''}">${{ traffic: 'Traffic', repeater: 'Repeater', status: 'Durum' }[k]}</button>`).join('')}</nav>` + (page === 'traffic' ? `<input id="search" placeholder="Trafikte ara..." value="${esc(q)}"><div class="layout"><div class="list">${reqs.map(r => `<div class="item ${r.id === selected ? 'selected' : ''}" data-id="${esc(r.id)}"><b>${esc(r.method)}</b> ${esc(r.status)}<div>${esc(r.url)}</div><small class="muted">${esc(r.type)} · ${r.duration || 0} ms</small></div>`).join('')}</div><div>${cur ? `<h3>${esc(cur.method)} · ${esc(cur.status)}</h3><p>${esc(cur.url)}</p><button id="to-rp">Repeater'a aktar</button><h4>Request Headers</h4><pre>${esc(hdr(cur.requestHeaders))}</pre><h4>Request Body</h4><pre>${esc(cur.requestBody)}</pre><h4>Response Headers</h4><pre>${esc(hdr(cur.responseHeaders))}</pre><h4>Response Body</h4><pre>${esc(cur.responseBody)}</pre>` : 'Henuz istek yok.'}</div></div>`
      : page === 'repeater' ? `<h3>Manuel istek</h3><select id="method">${['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map(m => `<option ${cur && cur.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select><input id="url" placeholder="URL" value="${esc(cur ? cur.url : '')}"><textarea id="headers" placeholder="Header: value">${esc(cur ? hdr(cur.requestHeaders) : '')}</textarea><textarea id="body" placeholder="Request body">${esc(cur ? cur.requestBody : '')}</textarea><button id="send">Gonder</button>`
        : `<h3>Baglanti durumu</h3><p>Toplam kayit: ${all.length}</p><p>Yakalama: ${data.active ? 'Aktif' : 'Duraklatildi'}</p>`);
    app.querySelectorAll('[data-tab]').forEach(b => { b.onclick = () => { page = b.dataset.tab; render(); }; });
    app.querySelectorAll('[data-id]').forEach(b => { b.onclick = () => { selected = b.dataset.id; render(); }; });
    const s = document.getElementById('search'); if (s) s.oninput = () => { q = s.value.toLowerCase(); const pos = s.selectionStart; render(); const n = document.getElementById('search'); n.focus(); n.setSelectionRange(pos, pos); };
    const t = document.getElementById('to-rp'); if (t) t.onclick = () => { page = 'repeater'; render(); };
    const sn = document.getElementById('send'); if (sn) sn.onclick = () => { ch.postMessage({ source: 'inspector-dashboard', type: 'MANUAL_SEND', data: { method: document.getElementById('method').value, url: document.getElementById('url').value, headers: document.getElementById('headers').value, body: document.getElementById('body').value } }); page = 'traffic'; render(); };
  }
  ch.onmessage = e => { const m = e.data; if (!m || m.source !== 'inspector-main') return; con.textContent = 'Canli baglanti'; if (m.type === 'SNAPSHOT' || m.type === 'TRAFFIC_UPDATE') { if (document.activeElement && /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && page !== 'traffic') { data = m.data; return; } data = m.data || { requests: [] }; render(); } };
  ch.postMessage({ source: 'inspector-dashboard', type: 'REQUEST_SNAPSHOT' });
  document.getElementById('fullscreen').onclick = async () => { try { document.fullscreenElement ? await document.exitFullscreen() : await document.documentElement.requestFullscreen(); } catch (e) {} };
  addEventListener('beforeunload', () => { try { ch.postMessage({ source: 'inspector-dashboard', type: 'DASHBOARD_CLOSED' }); ch.close(); } catch (e) {} });
}
const lite = r => ({ id: r.id, n: r.n, type: r.type, method: r.method, url: r.url, status: r.status, statusText: r.statusText, requestHeaders: shown(r.requestHeaders), responseHeaders: shown(r.responseHeaders), requestBody: limit(r.requestBody, 20000), responseBody: limit(r.responseBody, 20000), duration: r.duration, size: r.size, time: r.time });
function publish(type) {
  if (!S.tabMode || !S.channel) return;
  try { S.channel.postMessage({ source: 'inspector-main', type: type || 'TRAFFIC_UPDATE', data: { requests: S.requests.slice(0, 300).map(lite), selected: S.selected, active: S.on } }); } catch (e) {}
}
function setTabMode(on) {
  if (on && !S.tabMode) {
    if (!('BroadcastChannel' in W)) return toast('BroadcastChannel desteklenmiyor');
    S.channel = new BroadcastChannel(CHANNEL); S.tabMode = true;
    S.channel.onmessage = async e => {
      const m = e.data; if (!m || m.source !== 'inspector-dashboard') return;
      if (m.type === 'REQUEST_SNAPSHOT') publish('SNAPSHOT');
      if (m.type === 'MANUAL_SEND') { try { await sendRaw(m.data, 'manual'); } catch (err) { nativeConsole.error('Inspector:', err); } }
      if (m.type === 'DASHBOARD_CLOSED') S.dashboard = null;
    };
    publish('SNAPSHOT');
  } else if (!on && S.tabMode) {
    S.tabMode = false; try { S.channel.close(); } catch (e) {} S.channel = null;
    if (S.dashboard && !S.dashboard.closed) S.dashboard.close(); S.dashboard = null;
  }
  if (S.open && S.tab === 'settings') renderTab();
}
function openDashboard() {
  if (!S.tabMode) setTabMode(true);
  if (!S.tabMode) return;
  if (S.dashboard && !S.dashboard.closed) { S.dashboard.focus(); return; }
  const tab = W.open('', 'InspectorProDashboard');
  if (!tab) return toast('Yeni sekme acilamadi');
  S.dashboard = tab;
  tab.document.write(H(`<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Inspector Pro Dashboard</title><style>*{box-sizing:border-box}body{margin:0;background:#0f1319;color:#e7ebf2;font:13px system-ui}header{position:sticky;top:0;background:#161c25;padding:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;z-index:2}button{background:#1f2733;color:#fff;border:1px solid #2a3342;padding:9px 12px;border-radius:8px;cursor:pointer}button.active{background:#ff8a3d;color:#1a0d02;border-color:#ff8a3d;font-weight:700}main{padding:10px}nav{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}input,textarea,select{width:100%;background:#0a0e14;color:#fff;border:1px solid #2a3342;padding:9px;border-radius:8px;margin:4px 0;font-size:16px}textarea{min-height:80px;font-family:ui-monospace,monospace}.layout{display:grid;grid-template-columns:minmax(180px,32%) 1fr;gap:10px}.list{overflow:auto;max-height:78vh}.item{padding:9px;border-bottom:1px solid #2a3342;cursor:pointer;overflow-wrap:anywhere}.item.selected{background:#233044}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a0e14;padding:10px;border-radius:8px;max-height:300px;overflow:auto}.muted{color:#93a0b5}@media(max-width:650px){.layout{grid-template-columns:1fr}.list{max-height:30vh}}</style></head><body><header><b>Inspector Pro · Live</b><span id="connection">Baglaniyor...</span><button id="fullscreen">Tam ekran</button></header><main id="app">Veri bekleniyor...</main><script>(${dashMain.toString()})(${JSON.stringify(CHANNEL)});<\/script></body></html>`));
  tab.document.close();
}

/* ---------- OLAYLAR ---------- */
const icItem = () => S.icQueue.find(x => x.uid === S.icSel) || S.icQueue[0];

function setBound(n, v) {
  const [g, k] = n.split('.');
  if (n === 'note') { const r = selRec(); if (r) r.note = v; return; }
  if (g === 'icCfg') {
    S.icCfg[k] = v;
    saveIcCfg();
    if (k === 'filter') renderInterceptLists(true);
    return;
  }
  if (g === 'ic') {
    const i = icItem(); if (!i) return;
    if (i.kind === 'request') {
      if (k === 'hdr') i.hdr = v; else i.req[k] = v;
    } else if (i.kind === 'response') {
      if (k === 'status') i.status = Number(v) || 200;
      else if (k === 'statusText') i.statusText = v;
      else if (k === 'hdr') i.hdr = v;
      else if (k === 'body') i.body = v;
    } else if (i.kind === 'ws-out' || i.kind === 'ws-in') {
      if (k === 'data') i.data = v;
    }
    return;
  }
  if (g === 'rp') { const t = rpCur(); if (t) t[k] = v; return; }
  if (g === 'in') { S.in[k] = (k === 'delay' || k === 'conc') ? Math.max(0, Number(v) || 0) : v; if (k === 'sort') renderTab(); LS.set('intr', { method: S.in.method, url: S.in.url, headers: S.in.headers, body: S.in.body, payloads: S.in.payloads, type: S.in.type, delay: S.in.delay, conc: S.in.conc }); return; }
  if (g === 'dec') { S.dec[k] = v; return; }
  if (g === 'cmp') { S.cmp[k] = v; return; }
  if (g === 'nc') { S._nc[k] = v; return; }
  if (g === 'ns') { S._ns[k] = v; return; }
  if (g === 'nr') { S._nr[k] = v; return; }
  if (g === 'cons') return;
  if (g === 'sc') { S.scripts[k] = v; LS.set('scripts', S.scripts); return; }
  if (g === 'set') {
    if (['font', 'max', 'icTimeout', 'panelW', 'panelH'].includes(k)) v = Number(v) || 0;
    S.set[k] = v;
    if (k === 'panelW' || k === 'panelH') S.set.panelSizePreset = 'custom';
    if (k === 'max') { S.set.max = Math.max(50, Math.min(5000, v || 800)); while (S.requests.length > S.set.max) S.byId.delete(S.requests.pop().id); }
    if (k === 'font') S.set.font = Math.max(10, Math.min(20, v || 13));
    LS.set('set', S.set); applyTheme(); badges();
    if (EXT) W.postMessage({ __ipc: 'saveSet', set: S.set }, '*');
  }
}
function onInput(e) {
  const t = e.target; if (!(t instanceof Element)) return;
  if (t.dataset.f !== undefined) { S.f[t.dataset.f] = t.type === 'checkbox' ? t.checked : t.value; renderHistoryLists(true); return; }
  if (t.dataset.b) setBound(t.dataset.b, t.type === 'checkbox' ? t.checked : t.value);
}
function onChange(e) {
  const t = e.target; if (!(t instanceof Element)) return;
  if (t.dataset.chg === 'copyas') { const r = selRec(); if (r && t.value) copyAs(t.value, r); t.value = ''; return; }
  if (t.dataset.chg === 'cmpset') {
    const r = selRec(); const [side, what] = (t.value || ':').split(':'); t.value = ''; if (!r || !side) return;
    const txt = what === 'res' ? r.responseBody : what === 'req' ? r.requestBody : hdrText(shown(r.responseHeaders));
    S.cmp[side] = txt; S.cmp['l' + side] = '<- #' + r.n + ' ' + r.method + ' ' + pathOf(r.url).slice(0, 40); toast(side.toUpperCase() + ' dolduruldu'); return;
  }
  if (t.dataset.act === 'rule-on') { S.rules[+t.dataset.i].on = t.checked; LS.set('rules', S.rules); return; }
  if (t.dataset.icType) { S.icCfg.types[t.dataset.icType] = t.checked; saveIcCfg(); return; }
  if (t.dataset.icMethod) { S.icCfg.methods[t.dataset.icMethod] = t.checked; saveIcCfg(); return; }
  if (t.dataset.b && (t.tagName === 'SELECT' || t.type === 'checkbox')) {
    onInput(e);
    if (t.dataset.b === 'set.panelSizePreset' && S.open && S.tab === 'settings') renderTab();
  }
}
async function onClick(e) {
  const t = e.target; if (!(t instanceof Element)) return;
  const tabB = t.closest('[data-tab]'); if (tabB) { S.tab = tabB.dataset.tab; renderTabs(); renderTab(); return; }
  const icRow = t.closest('[data-ic-uid]');
  if (icRow) { S.icSel = icRow.dataset.icUid; S.icView = 'detail'; renderInterceptLists(true); return; }
  const el = t.closest('[data-act],[data-id]'); if (!el) return;
  const act = el.dataset.act;
  if (!act && el.dataset.id) { S.selected = el.dataset.id; S.view = 'detail'; detKey = ''; renderHistoryLists(true); return; }
  if (el.tagName === 'INPUT' && el.type === 'checkbox') return;
  const r = selRec(), i = Number(el.dataset.i), k = el.dataset.k;
  try {
    switch (act) {
      case 'pause': S.on = !S.on; badges(); toast(S.on ? 'Yakalama devam ediyor' : 'Yakalama durduruldu'); break;
      case 'full': setFull(!S.full); break;
      case 'hide': closePanel(); break;
      case 'back': S.view = 'list'; $('#split').className = 'split list'; sh.querySelector('.hist').classList.remove('dv'); break;
      case 'filters': S.showF = !S.showF; renderTab(); break;
      case 'hostclear': S.f.host = ''; renderTab(); break;
      case 'host-filter': if (r) { S.f.host = hostOf(r.url); S.view = 'list'; renderTab(); } break;
      case 'har': download('inspector-pro.har', JSON.stringify(toHAR(filtered()), null, 2)); break;
      case 'exp-json': download('inspector-pro.json', JSON.stringify({ app: 'inspector-pro', version: VER, requests: filtered().map(x => Object.assign({}, x, { requestHeaders: shown(x.requestHeaders), responseHeaders: shown(x.responseHeaders) })) }, null, 2)); break;
      case 'csv': download('inspector-pro.csv', 'n,time,method,status,type,url,ms,size\n' + filtered().map(x => [x.n, new Date(x.time).toISOString(), x.method, x.status, x.type, '"' + x.url.replace(/"/g, '""') + '"', x.duration || 0, x.size || 0].join(',')).join('\n'), 'text/csv'); break;
      case 'import': pickFile('.har,.json', importData); break;
      case 'clear': if (confirm('Tum kayitlar silinsin mi?')) { S.requests = []; S.byId.clear(); S.selected = null; S.view = 'list'; renderTab(); badges(); publish(); } break;
      case 'clear-star': S.requests.forEach(x => { x.star = false; }); renderTab(); break;
      case 'star': if (r) { r.star = !r.star; r._v++; renderHistoryLists(true); } break;
      case 'pretty': S.set.pretty = !S.set.pretty; LS.set('set', S.set); renderHistoryLists(true); break;
      case 'del': if (r) { S.requests = S.requests.filter(x => x !== r); S.byId.delete(r.id); S.selected = S.requests[0] ? S.requests[0].id : null; S.view = 'list'; renderHistoryLists(true); badges(); } break;
      case 'copy-bearer': if (r) { const bs = extractBearerTokens(r); if (bs[i]) copy(bs[i].full, 'Bearer token panoya kopyalandi'); } break;
      case 'to-rp': if (r) { rpNew(r); S.tab = 'repeater'; renderTabs(); renderTab(); } break;
      case 'to-in': if (r) { Object.assign(S.in, { method: r.method, url: r.url, headers: hdrText(r.requestHeaders), body: r.requestBody }); S.tab = 'intruder'; renderTabs(); renderTab(); toast('§ ile isaretle'); } break;

      /* mudahale */
      case 'ic-toggle-req':
        S.icCfg.reqOn = !S.icCfg.reqOn; saveIcCfg();
        if (!S.icCfg.reqOn) S.icQueue.filter(h => h.state === 'waiting' && h.kind === 'request').forEach(h => releaseIcItem(h, 'forward'));
        renderTab(); badges(); toast('Request Inspect: ' + (S.icCfg.reqOn ? 'ACIK' : 'KAPALI'));
        break;
      case 'ic-toggle-res':
        S.icCfg.resOn = !S.icCfg.resOn; saveIcCfg();
        if (!S.icCfg.resOn) S.icQueue.filter(h => h.state === 'waiting' && h.kind === 'response').forEach(h => releaseIcItem(h, 'forward'));
        renderTab(); badges(); toast('Response Inspect: ' + (S.icCfg.resOn ? 'ACIK' : 'KAPALI'));
        break;
      case 'ic-toggle-wsout':
        S.icCfg.wsOutOn = !S.icCfg.wsOutOn; saveIcCfg();
        if (!S.icCfg.wsOutOn) S.icQueue.filter(h => h.state === 'waiting' && h.kind === 'ws-out').forEach(h => releaseIcItem(h, 'forward'));
        renderTab(); badges(); toast('WS Giden Inspect: ' + (S.icCfg.wsOutOn ? 'ACIK' : 'KAPALI'));
        break;
      case 'ic-toggle-wsin':
        S.icCfg.wsInOn = !S.icCfg.wsInOn; saveIcCfg();
        if (!S.icCfg.wsInOn) S.icQueue.filter(h => h.state === 'waiting' && h.kind === 'ws-in').forEach(h => releaseIcItem(h, 'forward'));
        renderTab(); badges(); toast('WS Gelen Inspect: ' + (S.icCfg.wsInOn ? 'ACIK' : 'KAPALI'));
        break;
      case 'ic-toggle-settings':
        S.icCfg.showSettings = !S.icCfg.showSettings; saveIcCfg(); renderTab();
        break;
      case 'ic-back':
        S.icView = 'list'; renderInterceptLists(true);
        break;
      case 'ic-fwd': {
        const h = icItem();
        if (h && h.state === 'waiting') { releaseIcItem(h, 'forward'); renderInterceptLists(true); }
        break;
      }
      case 'ic-drop': {
        const h = icItem();
        if (h && h.state === 'waiting') { releaseIcItem(h, 'drop'); renderInterceptLists(true); }
        break;
      }
      case 'ic-fwdall':
        S.icQueue.filter(h => h.state === 'waiting').forEach(h => releaseIcItem(h, 'forward'));
        renderInterceptLists(true);
        break;
      case 'ic-dropall':
        S.icQueue.filter(h => h.state === 'waiting').forEach(h => releaseIcItem(h, 'drop'));
        renderInterceptLists(true);
        break;
      case 'ic-clear-done':
        S.icQueue = S.icQueue.filter(h => h.state === 'waiting');
        if (!S.icQueue.some(h => h.uid === S.icSel)) S.icSel = S.icQueue[0] ? S.icQueue[0].uid : null;
        renderInterceptLists(true); badges();
        break;
      case 'ic-rp': {
        const h = icItem();
        if (h) {
          const m = h.kind === 'request' ? h.req.method : h.method;
          const u = h.kind === 'request' ? h.req.url : h.url;
          const hd = h.kind === 'request' ? parseHdr(h.hdr) : {};
          const bd = h.kind === 'request' ? h.req.body : '';
          rpNew({ method: m, url: u, requestHeaders: hd, requestBody: bd }); S.tab = 'repeater'; renderTabs(); renderTab();
        }
        break;
      }
      case 'ic-to-hist': {
        const h = icItem();
        if (h && S.byId.has(h.id)) { S.selected = h.id; S.tab = 'history'; S.view = 'detail'; renderTabs(); renderTab(); }
        break;
      }

      /* repeater */
      case 'rp-send': rpSend(); break;
      case 'rp-add': rpNew(null); renderTab(); break;
      case 'rp-del': S.rp.tabs = S.rp.tabs.filter(x => x.id !== S.rp.cur); S.rp.cur = S.rp.tabs[0] ? S.rp.tabs[0].id : null; renderTab(); break;
      case 'rp-tab': S.rp.cur = el.dataset.id; renderTab(); break;
      case 'rp-rtab': rpCur().rtab = k; renderTab(); break;
      case 'rp-load': { const x = selRec(); if (x) { Object.assign(rpCur(), { method: x.method, url: x.url, headers: hdrText(x.requestHeaders), body: x.requestBody }); renderTab(); } break; }
      case 'rp-dup': { const c = rpCur(); const n = rpNew({ method: c.method, url: c.url, requestHeaders: parseHdr(c.headers), requestBody: c.body }); n.cred = c.cred; n.redirect = c.redirect; renderTab(); break; }
      case 'rp-to-in': { const c = rpCur(); Object.assign(S.in, { method: c.method, url: c.url, headers: c.headers, body: c.body }); S.tab = 'intruder'; renderTabs(); renderTab(); break; }
      case 'rp-copyres': { const c = rpCur(); if (c && c.resp) copy(c.resp.body || ''); break; }
      case 'rp-tocmp': { const c = rpCur(); if (c && c.resp) { S.cmp.a = c.resp.body; S.cmp.la = '<- repeater'; toast('A dolduruldu'); } break; }
      case 'rp-tocmpb': { const c = rpCur(); if (c && c.resp) { S.cmp.b = c.resp.body; S.cmp.lb = '<- repeater'; toast('B dolduruldu'); } break; }

      /* intruder / decoder / compare / target / page / rules / scripts */
      case 'in-run': runIntruder(); break;
      case 'in-clear': S.in.results = []; S.in.sel = null; renderTab(); break;
      case 'in-preset': S.in.payloads = PRESETS[k](); renderTab(); break;
      case 'in-sel': S.in.sel = i; renderTab(); break;
      case 'dec-run': await decRun(); break;
      case 'dec-move': S.dec.inp = S.dec.out; renderTab(); break;
      case 'dec-copy': copy(S.dec.out); break;
      case 'dec-cmp': S.cmp.a = S.dec.out; S.cmp.la = '<- decoder'; toast('A dolduruldu'); break;
      case 'cmp-run': cmpRun(); break;
      case 'cmp-swap': [S.cmp.a, S.cmp.b] = [S.cmp.b, S.cmp.a]; [S.cmp.la, S.cmp.lb] = [S.cmp.lb, S.cmp.la]; renderTab(); break;
      case 'tg-host': S.f.host = k; S.tab = 'history'; S.view = 'list'; renderTabs(); renderTab(); break;
      case 'tg-path': S.f.host = el.dataset.h; S.f.q = k; S.tab = 'history'; S.view = 'list'; renderTabs(); renderTab(); break;
      case 'pg': S.pg = k; renderTab(); break;
      case 'ck-save': { const c = ckList()[i]; const v = sh.querySelector('[data-ckv="' + i + '"]').value; D.cookie = c.k + '=' + v + '; path=/'; toast('Kaydedildi'); break; }
      case 'ck-del': { const c = ckList()[i]; D.cookie = c.k + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'; D.cookie = c.k + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT'; renderTab(); break; }
      case 'ck-add': if (S._nc.k) { D.cookie = S._nc.k + '=' + S._nc.v + '; path=/'; S._nc = { k: '', v: '' }; renderTab(); } break;
      case 'ck-copy': copy(D.cookie); break;
      case 'ck-clear': ckList().forEach(c => { D.cookie = c.k + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'; }); renderTab(); break;
      case 'st-save': { const c = S._st[i]; W[c.a].setItem(c.k, sh.querySelector('[data-stv="' + i + '"]').value); toast('Kaydedildi'); break; }
      case 'st-del': { const c = S._st[i]; W[c.a].removeItem(c.k); renderTab(); break; }
      case 'st-copy': copy(S._st[i].v); break;
      case 'st-add': if (S._ns.k) { try { W[S._ns.area].setItem(S._ns.k, S._ns.v); } catch (er) {} S._ns.k = S._ns.v = ''; renderTab(); } break;
      case 'fm-unlock': { let n = 0; D.querySelectorAll('input[type=hidden]').forEach(x => { x.type = 'text'; x.style.cssText += ';display:block;outline:2px dashed #ff8a3d'; n++; }); D.querySelectorAll('[disabled],[readonly],[maxlength],[required],[pattern]').forEach(x => { ['disabled', 'readonly', 'maxlength', 'required', 'pattern'].forEach(a => x.removeAttribute(a)); n++; }); toast(n + ' alan acildi'); break; }
      case 'scan-links': await scanLinks(); break;
      case 'scan-secrets': await scanSecrets(); break;
      case 'scan-sec': await scanSec(); break;
      case 'copy-list': { const l = S._res.links; if (l) copy((k === 'Yollar' ? l.paths : k === 'Parametreler' ? l.params : l.urls).join('\n')); break; }
      case 'cons-run': await consRun(); break;
      case 'cons-clear': S.cons = []; consRefresh(); break;
      case 'pick': startPick(); break;
      case 'dom-apply': { const x = S.picked; if (x) { const h = $('#dom-html').value; x.outerHTML = h; toast('Uygulandi'); S.picked = null; renderTab(); } break; }
      case 'dom-copy': if (S.picked) copy(S.picked.outerHTML); break;
      case 'dom-sel': if (S.picked) copy(cssPath(S.picked)); break;
      case 'dom-hide': if (S.picked) S.picked.style.setProperty('display', 'none', 'important'); break;
      case 'dom-del': if (S.picked) { S.picked.remove(); S.picked = null; renderTab(); } break;
      case 'dom-parent': if (S.picked && S.picked.parentElement) { S.picked = S.picked.parentElement; W.$0 = S.picked; renderTab(); } break;
      case 'src-find': { const ta = $('#src-t'), q = $('#src-q').value; if (!q) break; let p = ta.value.toLowerCase().indexOf(q.toLowerCase(), (ta.selectionEnd || 0)); if (p < 0) p = ta.value.toLowerCase().indexOf(q.toLowerCase()); if (p < 0) return toast('Bulunamadi'); ta.focus(); ta.setSelectionRange(p, p + q.length); break; }
      case 'src-copy': copy(D.documentElement.outerHTML); break;
      case 'rule-add': if (S._nr.match) { S.rules.push({ on: true, target: S._nr.target, match: S._nr.match, replace: S._nr.replace, regex: S._nr.regex }); LS.set('rules', S.rules); S._nr.match = S._nr.replace = ''; renderTab(); } else toast('Aranan bos'); break;
      case 'rule-del': S.rules.splice(i, 1); LS.set('rules', S.rules); renderTab(); break;
      case 'sc-tpl': if (SCRIPT_TEMPLATES[k]) { S.scripts.custom = SCRIPT_TEMPLATES[k]; LS.set('scripts', S.scripts); renderTab(); } break;
      case 'sc-run-custom': await runCustomScript(); break;
      case 'sc-clear-logs': S.scriptLogs = []; renderTab(); break;
      case 'tabmode': setTabMode(!S.tabMode); break;
      case 'opentab': openDashboard(); break;
      case 'destroy': if (confirm('Inspector Pro kaldirilsin mi?')) api.destroy(); break;
    }
  } catch (err) { toast('Hata: ' + (err && err.message || err)); nativeConsole.error(err); }
}
sh.addEventListener('click', onClick);
sh.addEventListener('input', onInput);
sh.addEventListener('change', onChange);
['keydown', 'keyup', 'keypress'].forEach(t => host.addEventListener(t, e => e.stopPropagation()));

(function () {
  let sx, sy, ox, oy, drag = false, down = false;
  const place = (x, y) => { x = Math.max(4, Math.min(W.innerWidth - 56, x)); y = Math.max(4, Math.min(W.innerHeight - 56, y)); launcher.style.left = x + 'px'; launcher.style.top = y + 'px'; launcher.style.right = 'auto'; launcher.style.bottom = 'auto'; return [x, y]; };
  const p = LS.get('pos', null); if (p) place(p[0], p[1]);
  launcher.addEventListener('pointerdown', e => { down = true; drag = false; sx = e.clientX; sy = e.clientY; const r = launcher.getBoundingClientRect(); ox = r.left; oy = r.top; try { launcher.setPointerCapture(e.pointerId); } catch (er) {} });
  launcher.addEventListener('pointermove', e => { if (!down) return; if (!drag && Math.abs(e.clientX - sx) + Math.abs(e.clientY - sy) > 8) drag = true; if (drag) place(ox + e.clientX - sx, oy + e.clientY - sy); });
  launcher.addEventListener('pointerup', () => { if (!down) return; down = false; if (drag) { const r = launcher.getBoundingClientRect(); LS.set('pos', [r.left, r.top]); } });
  launcher.addEventListener('click', () => { if (drag) { drag = false; return; } openPanel(); });
  launcher.addEventListener('pointercancel', () => { down = false; });
  W.addEventListener('resize', () => { if (launcher.style.left) { const r = launcher.getBoundingClientRect(); place(r.left, r.top); } fitViewport(); });
})();

D.addEventListener('pointerdown', e => {
  if (!S.open || S.full || !S.set.outside || picking) return;
  if (e.composedPath().indexOf(host) >= 0) return;
  closePanel();
  const swallow = ev => { ev.preventDefault(); ev.stopPropagation(); D.removeEventListener('click', swallow, true); };
  D.addEventListener('click', swallow, true); setTimeout(() => D.removeEventListener('click', swallow, true), 600);
}, true);
W.addEventListener('keydown', e => { if (e.altKey && e.shiftKey && e.code === 'KeyI') { e.preventDefault(); togglePanel(); } }, true);
if (W.visualViewport) { W.visualViewport.addEventListener('resize', fitViewport); W.visualViewport.addEventListener('scroll', fitViewport); }
if (W.ResizeObserver) new ResizeObserver(() => {
  const r = panel.getBoundingClientRect();
  if (!S.full && S.open && r.width > 0 && r.height > 0 && W.innerWidth >= 700) {
    const rw = Math.round(r.width), rh = Math.round(r.height);
    if (Math.abs(rw - (Number(S.set.panelW) || 680)) > 6 || Math.abs(rh - (Number(S.set.panelH) || 720)) > 6) {
      S.set.panelW = rw; S.set.panelH = rh; S.set.panelSizePreset = 'custom'; LS.set('set', S.set);
    }
  }
  panel.classList.toggle('wide', r.width >= 640);
  panel.classList.toggle('narrow', r.width < 640);
}).observe(panel);
if (W.matchMedia) { try { W.matchMedia('(prefers-color-scheme: light)').addEventListener('change', applyTheme); } catch (e) {} }

function persistSave() {
  if (!EXT || !S.set.persist) return;
  try { W.sessionStorage.setItem('ip5:hist', JSON.stringify(S.requests.slice(0, 150).map(r => Object.assign({}, r, { responseBody: limit(r.responseBody, 5000), requestBody: limit(r.requestBody, 5000), frames: undefined })))); } catch (e) {}
}
function persistLoad() {
  if (!EXT) return;
  try { const a = JSON.parse(W.sessionStorage.getItem('ip5:hist') || '[]'); a.reverse().forEach(r => { r.restored = true; r.id = r.id || uid(); addRecord(r); }); } catch (e) {}
}
function onBridge(e) {
  const d = e.data; if (e.source !== W || !d || !d.__ip) return;
  if (d.__ip === 'toggle') togglePanel();
  else if (d.__ip === 'show') openPanel();
  else if (d.__ip === 'cfg') {
    S.disabledSite = d.enabled === false || (d.blocked || []).indexOf(location.hostname) >= 0; S.netOn = d.net !== false;
    if (d.set) { Object.keys(d.set).forEach(k => { if (!(k in (LS.get('set', {})))) S.set[k] = d.set[k]; }); }
    if (S.disabledSite) { S.on = false; closePanel(); launcher.classList.add('hidden'); }
    else { S.on = true; if (!S.open) launcher.classList.remove('hidden'); if (d.startOpen || S.set.startOpen) { if (!S._autoOpened) { S._autoOpened = true; openPanel(); } } }
    applyTheme();
  } else if (d.__ip === 'net' && S.on && S.netOn !== false) {
    const x = d.rec; if (!x || /xmlhttprequest|ping/.test(x.type)) return;
    addRecord({ type: 'net', method: x.method, url: x.url, status: x.status == null ? 'pending' : x.status, statusText: x.statusText || '', requestHeaders: x.requestHeaders || {}, responseHeaders: x.responseHeaders || {}, duration: x.duration || 0, mime: x.mime || '', size: x.size || 0, time: x.time || Date.now(), netType: x.type, ip: x.ip, fromCache: x.fromCache, error: x.error, hasResponse: true });
  }
}
if (EXT) { W.addEventListener('message', onBridge); W.addEventListener('pagehide', persistSave); W.postMessage({ __ipc: 'hello' }, '*'); }

const api = {
  show: openPanel, hide: closePanel, toggle: togglePanel, openTab: openDashboard,
  enableTabMode() { setTabMode(true); }, disableTabMode() { setTabMode(false); },
  clear() { S.requests = []; S.byId.clear(); S.selected = null; badges(); publish(); if (S.open) renderTab(); },
  exportHAR() { download('inspector-pro.har', JSON.stringify(toHAR(S.requests), null, 2)); },
  manualSend: o => sendRaw(o, 'manual'),
  runScript: code => { S.scripts.custom = code; return runCustomScript(); },
  destroy() {
    S.on = false; setTabMode(false);
    if (nativeFetch) W.fetch = nativeFetch;
    XHR.prototype.open = xhrOpen; XHR.prototype.send = xhrSend; XHR.prototype.setRequestHeader = xhrHeader;
    if (NativeWS) W.WebSocket = NativeWS; if (NativeES) W.EventSource = NativeES; if (nativeBeacon) navigator.sendBeacon = nativeBeacon;
    ['log', 'info', 'warn', 'error', 'debug'].forEach(k => { console[k] = nativeConsole[k]; });
    host.remove(); delete W.__inspectorPro;
  },
  state: S
};
W.__inspectorPro = api;

function mount() {
  if (!host.isConnected) (D.documentElement || D).appendChild(host);
  applyTheme(); fitViewport(); badges();
}
mount(); persistLoad();
if (D.readyState === 'loading') D.addEventListener('DOMContentLoaded', mount);
if (!EXT) openPanel();
})();
