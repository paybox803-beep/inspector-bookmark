/*!
 * Inspector Pro v4.2 — in-page network inspector (yer imi + eklenti cekirdegi)
 * fetch · XHR · WebSocket · sendBeacon · console yakalama, Istek/Yanit/WS Mudahale,
 * Repeater, Intruder, Decoder, Karsilastir, Match&Replace, Script Lab, Sayfa araclari, HAR/JSON/CSV.
 * Yalnizca sahibi oldugun veya test izni aldigin sistemlerde kullan.
 */
(() => {
'use strict';
const W = window, D = document;
if (W.__inspectorPro) { try { W.__inspectorPro.show(); } catch (e) {} return; }

const EXT = !!W.__IP_EXT, VER = '4.2', CHANNEL = 'inspector-pro-live-v4';
const DEFAULT_ICON_URL = 'https://cdn.jsdelivr.net/npm/lucide-static@0.468.0/font/lucide.css';

const nativeFetch = W.fetch ? W.fetch.bind(W) : null;
const XHR = W.XMLHttpRequest;
const xhrOpen = XHR.prototype.open, xhrSend = XHR.prototype.send,
      xhrHeader = XHR.prototype.setRequestHeader, xhrAbort = XHR.prototype.abort;
const NativeWS = W.WebSocket;
const nativeBeacon = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;
const nativeConsole = {};
['log', 'info', 'warn', 'error', 'debug'].forEach(k => { nativeConsole[k] = console[k].bind(console); });

const LS = {
  get(k, d) { try { const v = W.localStorage.getItem('ip4:' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { W.localStorage.setItem('ip4:' + k, JSON.stringify(v)); } catch (e) {} }
};

let TTP = null;
try { if (W.trustedTypes && W.trustedTypes.createPolicy) TTP = W.trustedTypes.createPolicy('inspector-pro', { createHTML: x => x }); } catch (e) { try { TTP = W.trustedTypes.defaultPolicy || null; } catch (e2) {} }
const H = x => (TTP && TTP.createHTML ? TTP.createHTML(x) : x);

const DEFAULT_SET = {
  mask: true, bodies: true, max: 500, theme: 'auto', font: 13, outside: true,
  icTimeout: 0, pretty: true, persist: true, startOpen: false,
  panelW: 560, panelH: 680, panelSizePreset: 'standard', iconUrl: DEFAULT_ICON_URL
};

const S = {
  on: true, open: false, full: false, tab: 'history', view: 'list', showF: false,
  requests: [], byId: new Map(), seq: 0, selected: null,
  f: { q: '', method: '', status: '', type: '', star: false, regex: false, inBody: false, host: '' },
  set: Object.assign({}, DEFAULT_SET, LS.get('set', {})),
  rules: LS.get('rules', []),
  scripts: LS.get('scripts', { before: '', after: '' }),
  /* Istek mudahale */
  icOn: false, icStepMode: true, held: [], icSel: null, icFilter: '',
  /* Yanit mudahale */
  resIcOn: false, resHeld: [], resSel: null, resIcFilter: '',
  /* WebSocket mudahale */
  wsIcOn: false, wsIcDir: 'both', wsHeld: [], wsSel: null, wsIcFilter: '',
  /* Diger araclar */
  rp: { tabs: [], cur: null },
  in: Object.assign({ method: 'GET', url: '', headers: '', body: '', payloads: '', type: 'sniper', delay: 0, conc: 1, running: false, results: [], sel: null, sort: 'n' }, LS.get('intr', {})),
  cmp: { a: '', b: '', la: '', lb: '', mode: 'line' },
  dec: { inp: '', out: '', op: 'Akilli coz' },
  pg: 'cookies', cons: [], picked: null,
  tabMode: false, channel: null, dashboard: null, disabledSite: false
};

const sensitive = /authorization|cookie|token|secret|password|passwd|api[-_]?key|x-csrf|session/i;
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const safe = v => { try { return typeof v === 'string' ? v : (JSON.stringify(v, null, 2) || String(v)); } catch (e) { return String(v); } };
const limit = (v, n) => String(v == null ? '' : v).slice(0, n || 150000);
const abs = u => { try { return new URL(String(u), D.baseURI).href; } catch (e) { return String(u); } };
const hostOf = u => { try { return new URL(u).host; } catch (e) { return ''; } };
const pathOf = u => { try { const x = new URL(u); return x.pathname + x.search; } catch (e) { return String(u); } };
const fmtB = n => { n = Number(n) || 0; return n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB'; };
const isText = ct => !ct || /text|json|xml|javascript|html|x-www-form|svg|csv|graphql|yaml/i.test(ct);
const isBodyless = m => /^(GET|HEAD)$/i.test(m);
const clone = o => JSON.parse(JSON.stringify(o));

/* ---------- IKON SISTEMI (EMOJI YOK, DIS KAYNAK + SVG FALLBACK) ---------- */
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
    arrow: '<svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 8h10M9 4l4 4-4 4"/></svg>'
  };
  return `<span class="sym" aria-hidden="true">${map[name] || ''}</span>`;
}
function loadRemoteIcons(url) {
  const targetUrl = String(url || '').trim();
  if (!targetUrl) return;
  let link = sh.querySelector('#ip-remote-icon-css');
  if (!link) {
    link = D.createElement('link');
    link.id = 'ip-remote-icon-css';
    link.rel = 'stylesheet';
    sh.appendChild(link);
  }
  link.href = targetUrl;
}

function hdrObj(h) {
  const out = {};
  try {
    const en = (typeof Headers !== 'undefined' && h instanceof Headers) ? [...h.entries()] : Object.entries(h || {});
    en.forEach(([k, v]) => { out[k] = String(v); });
  } catch (e) {}
  return out;
}
const shown = o => { if (!S.set.mask) return o; const r = {}; Object.keys(o || {}).forEach(k => { r[k] = sensitive.test(k) ? '[REDACTED]' : o[k]; }); return r; };
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

/* ---------- KAYITLAR ---------- */
let rt = 0;
function refresh() { if (rt) return; rt = setTimeout(() => { rt = 0; liveUpdate(); }, 120); }
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
function patch(id, ch) { const r = S.byId.get(id); if (!r) return; Object.assign(r, ch); r._v++; refresh(); }
const selRec = () => S.byId.get(S.selected) || null;
const totalHeldCount = () => S.held.length + S.resHeld.length + S.wsHeld.length;

/* ---------- KURALLAR / HOOK / ISTEK-YANIT-WS MUDAHALE ---------- */
function runHook(code, request, response) {
  if (!code || !code.trim()) return;
  try { new Function('request', 'response', '"use strict";\n' + code)(request, response); }
  catch (e) { nativeConsole.warn('Inspector Script Lab:', e); toast('Script hatasi: ' + e.message); }
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

/* Istek mudahale */
function icMatch(cur) { return matchExpr(S.icFilter, cur.method + ' ' + cur.url); }
function hold(rec, cur) {
  return new Promise(resolve => {
    const item = { id: rec.id, req: clone(cur), hdr: hdrText(cur.headers), resolve, t: Date.now() };
    S.held.push(item); if (!S.icSel || S.icStepMode) S.icSel = item.id;
    patch(rec.id, { status: 'held' });
    if (!S.open) toast('Istek durduruldu -> Mudahale');
    badges(); if (S.open && S.tab === 'intercept') renderTab();
    const to = Number(S.set.icTimeout) || 0;
    if (to > 0) setTimeout(() => release(item, 'forward'), to * 1000);
  });
}
function release(item, action) {
  const i = S.held.indexOf(item); if (i < 0) return;
  S.held.splice(i, 1);
  if (S.icSel === item.id) S.icSel = S.held[0] ? S.held[0].id : null;
  const req = item.req; req.headers = parseHdr(item.hdr);
  patch(item.id, { status: action === 'drop' ? 'dropped' : 'pending' });
  item.resolve({ action, req });
  badges(); if (S.open && S.tab === 'intercept') renderTab();
}
async function pipeline(rec, cur) {
  applyRules(cur);
  runHook(S.scripts.before, cur, null);
  if (S.icOn && icMatch(cur)) {
    const d = await hold(rec, cur);
    if (d.action === 'drop') return null;
    Object.assign(cur, d.req);
  }
  return cur;
}

/* Yanit mudahale */
function resIcMatch(meta) { return matchExpr(S.resIcFilter, `${meta.method || ''} ${meta.status || ''} ${meta.url || ''}`); }
function resHold(rec, meta) {
  return new Promise(resolve => {
    const item = {
      id: rec.id, method: meta.method, url: meta.url,
      status: Number(meta.status) || 200, statusText: meta.statusText || 'OK',
      hdr: hdrText(meta.headers || {}), body: meta.body == null ? '' : String(meta.body),
      t: Date.now(), resolve
    };
    S.resHeld.push(item); if (!S.resSel || S.icStepMode) S.resSel = item.id;
    patch(rec.id, { status: 'res-held' });
    if (!S.open) toast('Yanit durduruldu -> Mudahale');
    badges(); if (S.open && S.tab === 'intercept') renderTab();
    const to = Number(S.set.icTimeout) || 0;
    if (to > 0) setTimeout(() => resRelease(item, 'forward'), to * 1000);
  });
}
function resRelease(item, action) {
  const i = S.resHeld.indexOf(item); if (i < 0) return;
  S.resHeld.splice(i, 1);
  if (S.resSel === item.id) S.resSel = S.resHeld[0] ? S.resHeld[0].id : null;
  const out = { action, status: Number(item.status) || 200, statusText: item.statusText || '', headers: parseHdr(item.hdr), body: item.body };
  patch(item.id, { status: action === 'drop' ? 'dropped' : out.status });
  item.resolve(out);
  badges(); if (S.open && S.tab === 'intercept') renderTab();
}

/* WebSocket mudahale */
function wsIcMatch(meta) { return matchExpr(S.wsIcFilter, `${meta.dir} ${meta.url} ${meta.data}`); }
function wsHold(rec, dir, url, data) {
  return new Promise(resolve => {
    const item = {
      id: uid(), recId: rec.id, dir, url,
      data: typeof data === 'string' ? data : describeBody(data),
      t: Date.now(), resolve
    };
    S.wsHeld.push(item); if (!S.wsSel || S.icStepMode) S.wsSel = item.id;
    if (!S.open) toast(`WS ${dir === 'out' ? 'giden' : 'gelen'} mesaj durduruldu`);
    badges(); if (S.open && S.tab === 'intercept') renderTab();
    const to = Number(S.set.icTimeout) || 0;
    if (to > 0) setTimeout(() => wsRelease(item, 'forward'), to * 1000);
  });
}
function wsRelease(item, action) {
  const i = S.wsHeld.indexOf(item); if (i < 0) return;
  S.wsHeld.splice(i, 1);
  if (S.wsSel === item.id) S.wsSel = S.wsHeld[0] ? S.wsHeld[0].id : null;
  item.resolve({ action, data: item.data });
  badges(); if (S.open && S.tab === 'intercept') renderTab();
}

/* ---------- FETCH ---------- */
if (nativeFetch) W.fetch = async function (input, init) {
  if (!S.on) return nativeFetch(input, init);
  let req;
  try { req = new Request(input, init); } catch (e) { return nativeFetch(input, init); }
  const id = uid(), t0 = performance.now();
  const needBody = S.set.bodies || S.icOn || hasRules() || (S.scripts.before || '').trim();
  let body = '';
  if (!isBodyless(req.method) && needBody) { try { body = await req.clone().text(); } catch (e) {} }
  const orig = { method: req.method, url: req.url, headers: hdrObj(req.headers), body };
  const cur = clone(orig);
  addRecord({ id, type: 'fetch', method: orig.method, url: orig.url, requestHeaders: orig.headers, requestBody: S.set.bodies ? limit(body) : '', status: 'pending' });
  let out = req;
  try {
    const res0 = await pipeline(S.byId.get(id) || { id }, cur);
    if (!res0) { patch(id, { status: 'dropped' }); throw new TypeError('Inspector Pro: istek dusuruldu'); }
    if (JSON.stringify(cur) !== JSON.stringify(orig)) {
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
    const needResBody = S.resIcOn || (textual && (S.rules.some(r => r.on && r.target === 'res-body') || (S.scripts.after || '').trim()));

    if (needResBody) {
      let txt0 = '';
      try { txt0 = await res.clone().text(); } catch (e) {}
      let fStatus = res.status, fStatusText = res.statusText, fHdrs = respHdrs, fBody = txt0, modRes = false;

      if (S.resIcOn && resIcMatch({ method: cur.method, status: res.status, url: cur.url })) {
        const d = await resHold(S.byId.get(id) || { id }, { method: cur.method, url: cur.url, status: res.status, statusText: res.statusText, headers: respHdrs, body: txt0 });
        if (d.action === 'drop') { patch(id, { status: 'dropped', duration: Math.round(performance.now() - t0) }); throw new TypeError('Inspector Pro: yanit dusuruldu'); }
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
        duration: Math.round(performance.now() - t0), modifiedResponse: modRes
      });
      return res;
    }

    const info = { status: res.status, statusText: res.statusText, responseHeaders: respHdrs, mime: ct.split(';')[0], redirected: res.redirected, finalUrl: res.url, duration: Math.round(performance.now() - t0), size: Number(res.headers.get('content-length')) || 0 };
    patch(id, info);
    if (S.set.bodies && textual && !/event-stream/.test(ct)) {
      res.clone().text().then(t => patch(id, { responseBody: limit(t), size: t.length })).catch(() => {});
    }
    return res;
  } catch (e) {
    const r = S.byId.get(id);
    if (!r || r.status !== 'dropped') patch(id, { status: 'error', error: String(e), duration: Math.round(performance.now() - t0) });
    throw e;
  }
};

/* ---------- XHR ---------- */
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
  addRecord({ id: m.id, type: 'xhr', method: m.method, url: m.url, requestHeaders: Object.assign({}, m.headers), requestBody: S.set.bodies ? limit(bstr) : '', status: 'pending' });

  const onDone = async () => {
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

    if (S.resIcOn && resIcMatch({ method: m.method, status: st, url: m.url })) {
      const d = await resHold(S.byId.get(m.id) || { id: m.id }, { method: m.method, url: m.url, status: st, statusText: stTxt, headers: rh, body: rb });
      if (d.action === 'drop') { patch(m.id, { status: 'dropped', duration: Math.round(performance.now() - t0) }); try { xhrAbort.call(self); } catch (e) {} return; }
      st = d.status; stTxt = d.statusText; rh = d.headers; outBody = d.body; modRes = true;
      try {
        Object.defineProperty(self, 'status', { configurable: true, get: () => st });
        Object.defineProperty(self, 'statusText', { configurable: true, get: () => stTxt });
        Object.defineProperty(self, 'responseText', { configurable: true, get: () => outBody });
        if (!self.responseType || self.responseType === 'text') Object.defineProperty(self, 'response', { configurable: true, get: () => outBody });
        else if (self.responseType === 'json') Object.defineProperty(self, 'response', { configurable: true, get: () => JSON.parse(outBody) });
      } catch (e) {}
    }
    patch(m.id, { status: st || 'error', statusText: stTxt, responseHeaders: rh, responseBody: S.set.bodies ? limit(outBody) : '', size: String(outBody).length || size, mime: (rh['content-type'] || '').split(';')[0], finalUrl: self.responseURL, duration: Math.round(performance.now() - t0), modifiedResponse: modRes });
  };
  this.addEventListener('loadend', onDone, { once: true });

  const go = b => xhrSend.call(self, b);
  if (!(m.async && (S.icOn || hasRules() || (S.scripts.before || '').trim()))) return go(body);
  const cur = { method: m.method, url: m.url, headers: Object.assign({}, m.headers), body: bstr };
  pipeline(S.byId.get(m.id) || { id: m.id }, cur).then(res => {
    if (!res) {
      patch(m.id, { status: 'dropped' });
      try { xhrAbort.call(self); } catch (e) {}
      try { self.dispatchEvent(new ProgressEvent('error')); self.dispatchEvent(new ProgressEvent('loadend')); } catch (e) {}
      return;
    }
    if (res.method !== m.method || res.url !== m.url || JSON.stringify(res.headers) !== JSON.stringify(m.headers)) {
      try {
        xhrOpen.call(self, res.method, res.url, true, m.user, m.pass);
        Object.keys(res.headers).forEach(k => { try { xhrHeader.call(self, k, res.headers[k]); } catch (e) {} });
        patch(m.id, { method: res.method, url: res.url, requestHeaders: res.headers, modified: true });
      } catch (e) {}
    }
    go(editable ? res.body : body);
  }).catch(() => go(body));
};

/* ---------- WebSocket / sendBeacon / console ---------- */
if (NativeWS) {
  const WS = function (url, protocols) {
    const ws = protocols === undefined ? new NativeWS(url) : new NativeWS(url, protocols);
    if (!S.on) return ws;
    const wsUrl = String(ws.url || url);
    const rec = addRecord({ type: 'ws', method: 'WS', url: wsUrl, status: 'open', frames: [] });
    const frame = (dir, d) => {
      const t = typeof d === 'string' ? d : describeBody(d);
      rec.frames.push({ dir, t: Date.now(), d: limit(t, 20000) }); if (rec.frames.length > 500) rec.frames.shift();
      rec.size = (rec.size || 0) + t.length; rec._v++; refresh();
    };

    const origSend = ws.send.bind(ws);
    ws.send = async function (d) {
      const rawStr = typeof d === 'string' ? d : describeBody(d);
      if (S.wsIcOn && (S.wsIcDir === 'both' || S.wsIcDir === 'out') && wsIcMatch({ dir: 'out', url: wsUrl, data: rawStr })) {
        const decision = await wsHold(rec, 'out', wsUrl, d);
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
      if (S.wsIcOn && (S.wsIcDir === 'both' || S.wsIcDir === 'in') && wsIcMatch({ dir: 'in', url: wsUrl, data: rawStr })) {
        const decision = await wsHold(rec, 'in', wsUrl, ev.data);
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
if (nativeBeacon) navigator.sendBeacon = function (url, data) {
  if (S.on) addRecord({ type: 'beacon', method: 'POST', url: abs(url), requestBody: limit(describeBody(data)), status: 'sent' });
  return nativeBeacon(url, data);
};
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
    if (rec) patch(id, { status: res.status, statusText: res.statusText, responseHeaders: out.headers, responseBody: limit(text), size, mime: out.mime, duration: out.ms, finalUrl: res.url });
    return out;
  } catch (e) { if (rec) patch(id, { status: 'error', error: String(e), duration: Math.round(performance.now() - t0) }); throw e; }
}

/* ================= ARAYUZ ================= */
const CSS = `
:host{all:initial;--bg:#0f1319;--bg2:#161c25;--bg3:#1f2733;--line:#2a3342;--txt:#e7ebf2;--mut:#93a0b5;--acc:#ff8a3d;--acc2:#3a2412;--ok:#3fb68b;--err:#ef5b5b;--warn:#e5b84b;--inp:#0a0e14;--sel:#233044;--fs:13px;--pw:560px;--ph:680px}
:host([data-theme=light]){--bg:#f5f6f8;--bg2:#fff;--bg3:#e8ecf2;--line:#d2d9e4;--txt:#1b2330;--mut:#5b687d;--acc:#d4601a;--acc2:#fde8d7;--ok:#1b8c66;--err:#cf3a3a;--warn:#9c7200;--inp:#fff;--sel:#dfe7f2}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
button,input,select,textarea{font:inherit;color:inherit}
.hidden{display:none!important}
.sym{display:inline-flex;align-items:center;justify-content:center;vertical-align:middle;line-height:1}
#launcher{position:fixed;z-index:2147483647;right:14px;bottom:calc(14px + env(safe-area-inset-bottom,0px));width:52px;height:52px;border-radius:50%;border:2px solid #ffffff33;background:var(--acc);color:#1a0d02;font:800 15px/1 system-ui,sans-serif;box-shadow:0 6px 22px #0008;cursor:pointer;touch-action:none;user-select:none}
#launcher .bd{position:absolute;top:-4px;right:-4px;min-width:20px;height:20px;padding:0 5px;border-radius:10px;background:var(--err);color:#fff;font:700 11px/20px system-ui;text-align:center}
#launcher .bd:empty{display:none}
#panel{position:fixed;z-index:2147483646;left:0;right:0;bottom:var(--vvb,0px);height:min(82dvh,calc(var(--vvh,100dvh) - 10px));display:flex;flex-direction:column;background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:16px 16px 0 0;box-shadow:0 -10px 40px #0009;font:var(--fs)/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow:hidden;padding-bottom:env(safe-area-inset-bottom,0px)}
@media(min-width:700px){#panel{left:auto;right:16px;bottom:calc(78px + var(--vvb,0px));width:min(var(--pw),calc(100vw - 32px));height:min(var(--ph),calc(var(--vvh,100dvh) - 100px));border-radius:14px;resize:both}}
#panel.full{left:0;right:0;top:0;bottom:var(--vvb,0px);width:auto;height:auto;border:0;border-radius:0;resize:none;padding-top:env(safe-area-inset-top,0px)}
.top{display:flex;align-items:center;gap:6px;padding:6px 8px;background:var(--bg2);border-bottom:1px solid var(--line)}
.brand{font-weight:800;margin-right:auto;letter-spacing:.2px}
.brand small{font-weight:500;color:var(--mut);margin-left:6px}
.stat{color:var(--mut);font-size:11px;white-space:nowrap}
.b{min-height:34px;padding:5px 11px;border-radius:8px;border:1px solid var(--line);background:var(--bg3);cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;justify-content:center;gap:5px}
.b:active{filter:brightness(1.25)}
.b.on,.b.pri{background:var(--acc);border-color:var(--acc);color:#1a0d02;font-weight:700}
.b.dng{color:var(--err);border-color:var(--err)}
.b.sm{min-height:28px;padding:2px 8px;font-size:12px}
.ic{min-width:36px;padding:5px 8px;font-size:14px}
#tabs{display:flex;gap:2px;overflow-x:auto;background:var(--bg2);border-bottom:1px solid var(--line);scrollbar-width:none;padding:0 4px}
#tabs::-webkit-scrollbar{display:none}
#tabs button{flex:none;min-height:40px;padding:0 12px;border:0;border-bottom:3px solid transparent;background:none;color:var(--mut);cursor:pointer;position:relative;font-weight:600}
#tabs button.on{color:var(--txt);border-bottom-color:var(--acc)}
#tabs .tb{margin-left:4px;padding:0 6px;border-radius:9px;background:var(--bg3);color:var(--txt);font-size:11px}
#tabs .tb.hot{background:var(--err);color:#fff}
#body{flex:1;min-height:0;overflow:auto;-webkit-overflow-scrolling:touch}
#body.flush{overflow:hidden}
.pad{padding:10px}
label{display:block;margin:9px 0 4px;color:var(--mut);font-size:12px}
label.ck{display:flex;align-items:center;gap:8px;color:var(--txt);font-size:inherit;margin:8px 0;min-height:30px}
input:not([type=checkbox]),textarea,select{width:100%;min-width:0;padding:8px 9px;background:var(--inp);color:var(--txt);border:1px solid var(--line);border-radius:8px;outline:none}
input:focus,textarea:focus,select:focus{border-color:var(--acc)}
input[type=checkbox]{width:18px;height:18px;accent-color:var(--acc);flex:none}
textarea{min-height:76px;resize:vertical;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre;overflow:auto}
textarea.wrap{white-space:pre-wrap}
@media(pointer:coarse){input:not([type=checkbox]),textarea,select{font-size:16px}textarea{font-size:13px}.b{min-height:40px}.b.sm{min-height:32px}}
.row{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:6px 0}
.row>.grow{flex:1;min-width:120px}
.mut{color:var(--mut)}.hint{color:var(--mut);font-size:12px;margin:6px 0}
.empty{color:var(--mut);padding:18px 10px;text-align:center}
.bar{display:flex;gap:6px;padding:7px 8px 0}
.filters{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;padding:6px 8px 0}
.filters .ck{margin:0;min-height:30px;font-size:12px}
.tools{padding:6px 8px;overflow-x:auto;scrollbar-width:none;flex-wrap:nowrap}
.hist{display:flex;flex-direction:column;height:100%}
.split{flex:1;min-height:0;display:grid;border-top:1px solid var(--line)}
.list,.detail{overflow:auto;min-width:0;-webkit-overflow-scrolling:touch}
.narrow .split{grid-template-columns:1fr}
.narrow .hist.dv>.bar,.narrow .hist.dv>.filters{display:none}
.narrow .split.list .detail,.narrow .split.detail .list{display:none}
.wide .split{grid-template-columns:minmax(170px,38%) 1fr}
.wide .list{border-right:1px solid var(--line)}
.wide .back{display:none}
.it{padding:8px 10px;border-bottom:1px solid var(--line);cursor:pointer;min-width:0}
.it.sel{background:var(--sel);box-shadow:inset 3px 0 var(--acc)}
.l1{display:flex;align-items:center;gap:6px;min-width:0}
.path{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.l2{color:var(--mut);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.m{font:700 11px ui-monospace,Menlo,monospace;padding:1px 5px;border-radius:5px;background:var(--bg3)}
.m-POST,.m-PUT,.m-PATCH{color:var(--warn)}.m-DELETE{color:var(--err)}.m-GET{color:var(--ok)}
.st{font:700 11px ui-monospace,Menlo,monospace;padding:1px 6px;border-radius:5px;background:var(--bg3);color:var(--mut)}
.st.s2{color:var(--ok)}.st.s3{color:#6ab0ff}.st.s4{color:var(--warn)}.st.s5,.st.er{color:var(--err)}.st.hl{color:#1a0d02;background:var(--acc)}
.star{color:var(--warn);font-style:normal}
.detail{padding:10px}
.dh{display:flex;align-items:center;gap:8px;margin-bottom:6px}
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
.chips{display:flex;gap:6px;overflow-x:auto;margin:6px 0;scrollbar-width:none}
.chips .b{flex:none}
.sub{display:flex;gap:4px;overflow-x:auto;padding:8px 8px 0;scrollbar-width:none}
.sub button{flex:none;min-height:32px;padding:0 12px;border-radius:16px;border:1px solid var(--line);background:var(--bg2);cursor:pointer}
.sub button.on{background:var(--acc);border-color:var(--acc);color:#1a0d02;font-weight:700}
ins{background:#3fb68b33;text-decoration:none;color:var(--ok)}del{background:#ef5b5b33;color:var(--err);text-decoration:line-through}
.diff{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 ui-monospace,Menlo,monospace;background:var(--inp);border:1px solid var(--line);border-radius:8px;padding:8px;max-height:55vh;overflow:auto}
.diff .ln{display:block}.diff .ln.a{background:#3fb68b22}.diff .ln.d{background:#ef5b5b22}
.cl{display:flex;gap:6px;padding:3px 0;border-bottom:1px solid var(--line);font:12px ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
.cl.warn{color:var(--warn)}.cl.error{color:var(--err)}.cl.info{color:#6ab0ff}
.fr{padding:3px 6px;border-radius:5px;margin:3px 0;font:12px ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
.fr.in{background:#3fb68b1f}.fr.out{background:#ff8a3d1f}
.card{border:1px solid var(--line);background:var(--bg2);border-radius:10px;padding:10px;margin:10px 0}
.card h4{margin:0 0 6px;font-size:13px}
#toast{position:fixed;z-index:2147483647;left:50%;bottom:calc(76px + env(safe-area-inset-bottom,0px));transform:translateX(-50%);max-width:88vw;background:#000d;color:#fff;padding:9px 14px;border-radius:10px;font:13px system-ui;pointer-events:none;opacity:0;transition:opacity .2s}
#toast.on{opacity:1}
#hl{position:fixed;z-index:2147483645;pointer-events:none;border:2px solid var(--acc);background:#ff8a3d33;display:none}
`;

const host = D.createElement('div');
host.id = '__ip_host';
const sh = host.attachShadow({ mode: 'open' });
sh.innerHTML = H(`<style>${CSS}</style>
<button id="launcher" title="Inspector Pro">IP<span class="bd"></span></button>
<section id="panel" class="hidden narrow">
 <div class="top"><span class="brand">Inspector Pro<small>${VER}</small></span><span class="stat" id="stat"></span>
  <button class="b ic" data-act="pause" title="Yakalamayi durdur/devam et">${svgSym('pause')}</button>
  <button class="b ic" data-act="full" title="Tam ekran">${svgSym('expand')}</button>
  <button class="b ic" data-act="hide" title="Kucult">${svgSym('close')}</button></div>
 <nav id="tabs"></nav>
 <main id="body"></main>
</section><div id="toast"></div><div id="hl"></div>`);
const $ = q => sh.querySelector(q);
const panel = $('#panel'), launcher = $('#launcher'), bodyEl = $('#body');
const TABS = [
  ['history', 'Istekler'], ['intercept', 'Mudahale'], ['repeater', 'Repeater'],
  ['intruder', 'Intruder'], ['decoder', 'Decoder'], ['compare', 'Karsilastir'],
  ['target', 'Hedef'], ['page', 'Sayfa'], ['rules', 'Kurallar'],
  ['guide', 'Kilavuz'], ['settings', 'Ayarlar']
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
  const presets = { compact: [420, 500], standard: [560, 680], wide: [780, 740] };
  let w = Number(S.set.panelW) || 560, h = Number(S.set.panelH) || 680;
  if (S.set.panelSizePreset && S.set.panelSizePreset !== 'custom' && presets[S.set.panelSizePreset]) {
    [w, h] = presets[S.set.panelSizePreset];
    S.set.panelW = w; S.set.panelH = h;
  }
  w = Math.max(320, Math.min(1600, w));
  h = Math.max(280, Math.min(1200, h));
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
  const held = totalHeldCount();
  const b = launcher.querySelector('.bd');
  b.textContent = held ? String(held) : '';
  const tb = sh.querySelector('[data-tab=intercept] .tb');
  if (tb) { tb.textContent = held || ''; tb.classList.toggle('hot', !!held); tb.style.display = held ? '' : 'none'; }
  const th = sh.querySelector('[data-tab=history] .tb'); if (th) th.textContent = S.requests.length;
  const st = $('#stat'); if (st) st.textContent = (S.on ? 'AKTIF ' : 'DURDU ') + S.requests.length;
  const pb = sh.querySelector('[data-act=pause]');
  if (pb) { pb.classList.toggle('on', !S.on); pb.innerHTML = H(svgSym(S.on ? 'pause' : 'play')); }
}
function renderTabs() {
  const held = totalHeldCount();
  $('#tabs').innerHTML = H(TABS.map(([k, l]) => `<button data-tab="${k}" class="${S.tab === k ? 'on' : ''}">${l}${k === 'history' ? `<span class="tb">${S.requests.length}</span>` : k === 'intercept' ? `<span class="tb ${held ? 'hot' : ''}" style="${held ? '' : 'display:none'}">${held}</span>` : ''}</button>`).join(''));
}
function renderTab() {
  bodyEl.classList.toggle('flush', S.tab === 'history');
  const map = { history: renderHistory, intercept: renderIntercept, repeater: renderRepeater, intruder: renderIntruder, decoder: renderDecoder, compare: renderCompare, target: renderTarget, page: renderPage, rules: renderRules, guide: renderGuide, settings: renderSettings };
  bodyEl.innerHTML = H(map[S.tab]());
  sh.querySelectorAll('[data-tab]').forEach(b => b.classList.toggle('on', b.dataset.tab === S.tab));
  if (S.tab === 'history') renderHistoryLists(true);
  if (S.tab === 'page') pageAfter();
  badges();
}
function liveUpdate() {
  badges();
  if (S.open && S.tab === 'history') renderHistoryLists();
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
 <div class="bar"><input id="f-q" type="search" placeholder="URL, method, durum, govde ara..." value="${esc(S.f.q)}" data-f="q"><button class="b ${S.showF ? 'on' : ''}" data-act="filters">Filtre</button></div>
 <div class="filters ${S.showF ? '' : 'hidden'}">
  ${sel('method', [['', 'Method'], ['GET', 'GET'], ['POST', 'POST'], ['PUT', 'PUT'], ['PATCH', 'PATCH'], ['DELETE', 'DELETE'], ['OPTIONS', 'OPTIONS'], ['WS', 'WS']], S.f.method)}
  ${sel('status', [['', 'Durum'], ['2', '2xx'], ['3', '3xx'], ['4', '4xx'], ['5', '5xx'], ['err', 'Hata']], S.f.status)}
  ${sel('type', [['', 'Tur'], ['fetch', 'fetch'], ['xhr', 'xhr'], ['ws', 'websocket'], ['beacon', 'beacon'], ['manual', 'manuel'], ['intruder', 'intruder'], ['net', 'ag'], ['import', 'ice aktarilan']], S.f.type)}
  <label class="ck"><input type="checkbox" data-f="star" ${S.f.star ? 'checked' : ''}>${svgSym('star')} yildizli</label>
  <label class="ck"><input type="checkbox" data-f="regex" ${S.f.regex ? 'checked' : ''}>regex</label>
  <label class="ck"><input type="checkbox" data-f="inBody" ${S.f.inBody ? 'checked' : ''}>govdede ara</label>
  ${S.f.host ? `<button class="b sm" data-act="hostclear" style="grid-column:1/-1">host: ${esc(S.f.host)} ${svgSym('close')}</button>` : ''}
 </div>
 <div class="bar tools row"><button class="b sm" data-act="har">HAR</button><button class="b sm" data-act="exp-json">JSON</button><button class="b sm" data-act="csv">CSV</button><button class="b sm" data-act="import">Ice aktar</button><button class="b sm" data-act="clear-star">Yildiz temizle</button><button class="b sm dng" data-act="clear">Temizle</button></div>
 <div class="split ${S.view}" id="split"><div class="list" id="ip-list"></div><div class="detail" id="ip-detail"></div></div></div>`;
}
function itemHTML(r) {
  return `<div class="it ${r.id === S.selected ? 'sel' : ''}" data-id="${esc(r.id)}"><div class="l1"><b class="m m-${esc(r.method)}">${esc(r.method)}</b><span class="st ${stc(r)}">${esc(stLabel(r))}</span>${r.star ? '<i class="star">*</i>' : ''}<span class="path">${esc(pathOf(r.url))}</span></div><div class="l2">${esc(hostOf(r.url))} · ${esc(r.type)}${r.modified ? ' · istek degisti' : ''}${r.modifiedResponse ? ' · yanit degisti' : ''}${r.duration ? ' · ' + r.duration + ' ms' : ''}${r.size ? ' · ' + fmtB(r.size) : ''}</div></div>`;
}
let detKey = '';
function renderHistoryLists(force) {
  const list = $('#ip-list'), det = $('#ip-detail'); if (!list) return;
  const items = filtered(), top = list.scrollTop;
  list.innerHTML = H(items.length ? items.slice(0, 400).map(itemHTML).join('') + (items.length > 400 ? `<div class="empty">+${items.length - 400} kayit daha — filtreyi daralt</div>` : '') : '<div class="empty">Henuz istek yok.<br>Sayfada gezin veya bir islem yapin; fetch, XHR, WebSocket ve beacon trafigi burada gorunur.</div>');
  list.scrollTop = top;
  const r = selRec(), key = r ? r.id + ':' + r._v + ':' + S.set.pretty + ':' + S.set.mask : '';
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
  const rq = shown(r.requestHeaders), rs = shown(r.responseHeaders);
  return `<div class="dh"><button class="b back" data-act="back">${svgSym('back')} Liste</button><div><b class="m m-${esc(r.method)}">${esc(r.method)}</b> <span class="st ${stc(r)}">${esc(stLabel(r))}</span> <span class="mut">${esc(r.statusText || '')}</span></div></div>
<div class="url">${esc(r.url)}</div>
<div class="row"><button class="b sm pri" data-act="to-rp">${svgSym('arrow')} Repeater</button><button class="b sm" data-act="to-in">${svgSym('arrow')} Intruder</button><button class="b sm ${r.star ? 'on' : ''}" data-act="star">${svgSym('star')}</button><button class="b sm" data-act="pretty">${S.set.pretty ? 'Pretty' : 'Raw'}</button><button class="b sm" data-act="host-filter">Host</button><button class="b sm dng" data-act="del">Sil</button></div>
<div class="row"><select class="grow" data-chg="copyas"><option value="">Kopyala...</option><option value="curl">cURL</option><option value="fetch">fetch()</option><option value="py">Python requests</option><option value="rawreq">Ham istek</option><option value="rawres">Ham yanit</option><option value="url">URL</option><option value="resbody">Yanit govdesi</option><option value="reqbody">Istek govdesi</option></select>
<select class="grow" data-chg="cmpset"><option value="">Karsilastir...</option><option value="a:res">A &lt;- yanit govdesi</option><option value="b:res">B &lt;- yanit govdesi</option><option value="a:req">A &lt;- istek govdesi</option><option value="b:req">B &lt;- istek govdesi</option><option value="a:hdr">A &lt;- yanit header</option><option value="b:hdr">B &lt;- yanit header</option></select></div>
<details open><summary>Genel</summary><div><table><tr><td>Tur</td><td>${esc(r.type)}${r.modified ? ' · <b>istek degistirildi</b>' : ''}${r.modifiedResponse ? ' · <b>yanit degistirildi</b>' : ''}</td></tr><tr><td>Sure / boyut</td><td>${r.duration || 0} ms · ${fmtB(r.size)}</td></tr><tr><td>MIME</td><td>${esc(r.mime || '-')}</td></tr>${r.finalUrl && r.finalUrl !== r.url ? `<tr><td>Son URL</td><td>${esc(r.finalUrl)}</td></tr>` : ''}${r.error ? `<tr><td>Hata</td><td>${esc(r.error)}</td></tr>` : ''}</table></div></details>
${q.length ? `<details><summary>Query <small>${q.length}</small></summary><div><table>${q.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('')}</table></div></details>` : ''}
<details open><summary>Istek header <small>${Object.keys(rq).length}</small></summary><pre>${esc(hdrText(rq)) || '(yok)'}</pre></details>
<details ${r.requestBody ? 'open' : ''}><summary>Istek govdesi <small>${fmtB(r.requestBody.length)}</small></summary><pre>${esc(bodyView(r.requestBody))}</pre></details>
<details><summary>Yanit header <small>${Object.keys(rs).length}</small></summary><pre>${esc(hdrText(rs)) || '(yok)'}</pre></details>
${r.type === 'ws' ? `<details open><summary>Mesajlar <small>${(r.frames || []).length}</small></summary><div>${(r.frames || []).slice(-150).map(f => `<div class="fr ${f.dir}">${f.dir === 'in' ? svgSym('down') : svgSym('up')} ${esc(limit(f.d, 600))}</div>`).join('') || '(yok)'}</div></details>` : `<details open><summary>Yanit govdesi <small>${fmtB(r.responseBody.length)}</small></summary><pre class="tall">${esc(bodyView(r.responseBody))}</pre></details>`}
${jwts.length ? `<details><summary>JWT <small>${jwts.length}</small></summary><div>${jwts.map(j => `<pre>${esc(jwtDecode(j))}</pre>`).join('<br>')}</div></details>` : ''}
<label>Not</label><textarea class="wrap" data-b="note" style="min-height:50px">${esc(r.note || '')}</textarea>`;
}
const qsafe = v => "'" + String(v == null ? '' : v).replace(/'/g, "'\\''") + "'";
const hdrsOut = r => shown(r.requestHeaders);
function asCurl(r) { let o = 'curl -i -X ' + qsafe(r.method) + ' ' + qsafe(r.url); Object.entries(hdrsOut(r)).forEach(([k, v]) => { o += ' \\\n  -H ' + qsafe(k + ': ' + v); }); if (r.requestBody) o += ' \\\n  --data-raw ' + qsafe(r.requestBody); return o; }
function asFetch(r) { const o = { method: r.method, headers: hdrsOut(r), credentials: 'include' }; if (r.requestBody && !isBodyless(r.method)) o.body = r.requestBody; return 'fetch(' + JSON.stringify(r.url) + ', ' + JSON.stringify(o, null, 2) + ')\n  .then(r => r.text()).then(console.log);'; }
function asPy(r) { return 'import requests\n\nr = requests.request(' + JSON.stringify(r.method) + ', ' + JSON.stringify(r.url) + ',\n    headers=' + JSON.stringify(hdrsOut(r), null, 4) + ',\n    data=' + JSON.stringify(r.requestBody || '') + ')\nprint(r.status_code)\nprint(r.text)'; }
const rawReq = r => { let u; try { u = new URL(r.url); } catch (e) { u = { pathname: r.url, search: '', host: '' }; } return r.method + ' ' + u.pathname + u.search + ' HTTP/1.1\nHost: ' + u.host + '\n' + hdrText(hdrsOut(r)) + '\n\n' + (r.requestBody || ''); };
const rawRes = r => 'HTTP/1.1 ' + r.status + ' ' + (r.statusText || '') + '\n' + hdrText(shown(r.responseHeaders)) + '\n\n' + (r.responseBody || '');
function copyAs(k, r) {
  const m = { curl: asCurl, fetch: asFetch, py: asPy, rawreq: rawReq, rawres: rawRes, url: x => x.url, resbody: x => x.responseBody, reqbody: x => x.requestBody };
  if (m[k]) copy(m[k](r));
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
        addRecord({ type: 'import', method: e.request.method, url: e.request.url, requestHeaders: h(e.request.headers), requestBody: e.request.postData ? e.request.postData.text || '' : '', status: e.response.status, statusText: e.response.statusText, responseHeaders: h(e.response.headers), responseBody: e.response.content ? e.response.content.text || '' : '', mime: e.response.content ? e.response.content.mimeType : '', duration: Math.round(e.time || 0), size: e.response.content ? e.response.content.size : 0, time: Date.parse(e.startedDateTime) || Date.now() }); n++; });
    } else if (j.app === 'inspector-pro') { j.requests.slice().reverse().forEach(r => { delete r.id; r.type = r.type || 'import'; addRecord(r); n++; }); }
    toast(n + ' kayit ice aktarildi'); renderTab();
  } catch (e) { toast('Dosya okunamadi: ' + e.message); }
}

/* ---------- MUDAHALE (ISTEK + YANIT + WEBSOCKET) ---------- */
function renderIntercept() {
  const it = S.held.find(x => x.id === S.icSel) || S.held[0];
  const rit = S.resHeld.find(x => x.id === S.resSel) || S.resHeld[0];
  const wit = S.wsHeld.find(x => x.id === S.wsSel) || S.wsHeld[0];

  return `<div class="pad">
<div class="card">
  <h4>1. HTTP Istek Mudahalesi (fetch / XHR)</h4>
  <div class="row">
    <button class="b sm ${S.icOn ? 'pri' : ''}" data-act="ic-toggle">Istek Mudahale: ${S.icOn ? 'ACIK' : 'KAPALI'}</button>
    <label class="ck" style="margin:0"><input type="checkbox" data-act="ic-step" ${S.icStepMode ? 'checked' : ''}>Yeni gelene odaklan</label>
    <span class="mut">${S.held.length} bekliyor</span>
  </div>
  <label>Istek Filtresi (metin veya /regex/)</label>
  <input data-b="ic.filter" value="${esc(S.icFilter)}" placeholder="/api/ veya POST">
  ${S.held.length > 1 ? `<div class="chips">${S.held.map((h, i) => `<button class="b sm ${h.id === (it && it.id) ? 'on' : ''}" data-act="ic-pick" data-id="${esc(h.id)}">#${i + 1} ${esc(h.req.method)}</button>`).join('')}</div>` : ''}
  ${it ? `
    <label>Method</label><select data-b="ic.method">${['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map(m => `<option ${it.req.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select>
    <label>URL</label><input data-b="ic.url" value="${esc(it.req.url)}">
    <label>Header</label><textarea data-b="ic.hdr">${esc(it.hdr)}</textarea>
    <label>Govde</label><textarea data-b="ic.body">${esc(it.req.body)}</textarea>
    <div class="row">
      <button class="b sm pri" data-act="ic-fwd">Ilet</button>
      <button class="b sm dng" data-act="ic-drop">Dusur</button>
      <button class="b sm" data-act="ic-rp">Repeater'a</button>
      <button class="b sm" data-act="ic-fwdall">Tumunu Ilet</button>
      <button class="b sm" data-act="ic-dropall">Tumunu Dusur</button>
    </div>` : '<div class="empty">Bekleyen istek yok.</div>'}
</div>

<div class="card">
  <h4>2. HTTP Yanit Mudahalesi (fetch / XHR)</h4>
  <div class="row">
    <button class="b sm ${S.resIcOn ? 'pri' : ''}" data-act="res-toggle">Yanit Mudahale: ${S.resIcOn ? 'ACIK' : 'KAPALI'}</button>
    <span class="mut">${S.resHeld.length} yanit bekliyor</span>
  </div>
  <label>Yanit Filtresi (method, durum kodu veya URL)</label>
  <input data-b="res.filter" value="${esc(S.resIcFilter)}" placeholder="/user veya 200">
  ${S.resHeld.length > 1 ? `<div class="chips">${S.resHeld.map((item, i) => `<button class="b sm ${item.id === (rit && rit.id) ? 'on' : ''}" data-act="res-pick" data-id="${esc(item.id)}">#${i + 1} ${item.status}</button>`).join('')}</div>` : ''}
  ${rit ? `
    <div class="hint">${esc(rit.method)} · <code>${esc(rit.url)}</code></div>
    <div class="row">
      <div class="grow"><label>Durum Kodu</label><input type="number" data-b="res.status" value="${rit.status}"></div>
      <div class="grow"><label>Durum Metni</label><input data-b="res.statusText" value="${esc(rit.statusText)}"></div>
    </div>
    <label>Yanit Header</label><textarea data-b="res.hdr">${esc(rit.hdr)}</textarea>
    <label>Yanit Govdesi</label><textarea data-b="res.body">${esc(rit.body)}</textarea>
    <div class="row">
      <button class="b sm pri" data-act="res-fwd">Yaniti Ilet</button>
      <button class="b sm dng" data-act="res-drop">Yaniti Dusur</button>
      <button class="b sm" data-act="res-fwdall">Tum Yanitlari Ilet</button>
      <button class="b sm" data-act="res-dropall">Tum Yanitlari Dusur</button>
    </div>` : '<div class="empty">Bekleyen yanit yok.</div>'}
</div>

<div class="card">
  <h4>3. WebSocket Mesaj Mudahalesi</h4>
  <div class="row">
    <button class="b sm ${S.wsIcOn ? 'pri' : ''}" data-act="ws-toggle">WS Mudahale: ${S.wsIcOn ? 'ACIK' : 'KAPALI'}</button>
    <select data-b="ws.dir" style="width:140px">
      <option value="both" ${S.wsIcDir === 'both' ? 'selected' : ''}>Giden + Gelen</option>
      <option value="out" ${S.wsIcDir === 'out' ? 'selected' : ''}>Sadece Giden</option>
      <option value="in" ${S.wsIcDir === 'in' ? 'selected' : ''}>Sadece Gelen</option>
    </select>
    <span class="mut">${S.wsHeld.length} WS bekliyor</span>
  </div>
  <label>WS Filtresi</label>
  <input data-b="ws.filter" value="${esc(S.wsIcFilter)}" placeholder="URL veya mesaj icerigi">
  ${S.wsHeld.length > 1 ? `<div class="chips">${S.wsHeld.map((w, i) => `<button class="b sm ${w.id === (wit && wit.id) ? 'on' : ''}" data-act="ws-pick" data-id="${esc(w.id)}">#${i + 1} ${w.dir.toUpperCase()}</button>`).join('')}</div>` : ''}
  ${wit ? `
    <div class="hint">Yon: <b>${wit.dir === 'out' ? 'Giden' : 'Gelen'}</b> · <code>${esc(wit.url)}</code></div>
    <label>Mesaj</label><textarea data-b="ws.data">${esc(wit.data)}</textarea>
    <div class="row">
      <button class="b sm pri" data-act="ws-fwd">Mesaji Ilet</button>
      <button class="b sm dng" data-act="ws-drop">Mesaji Dusur</button>
      <button class="b sm" data-act="ws-fwdall">Tum WS Ilet</button>
      <button class="b sm" data-act="ws-dropall">Tum WS Dusur</button>
    </div>` : '<div class="empty">Bekleyen WebSocket mesaji yok.</div>'}
</div>
</div>`;
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
<div class="row"><button class="b sm" data-act="rp-copyres">Yaniti kopyala</button><button class="b sm" data-act="rp-tocmp">Karsilastir A</button><button class="b sm" data-act="rp-tocmpb">Karsilastir B</button></div>`;
  return `<div class="pad"><div class="chips">${S.rp.tabs.map(x => `<button class="b sm ${x.id === t.id ? 'on' : ''}" data-act="rp-tab" data-id="${x.id}">${esc(x.name)}</button>`).join('')}<button class="b sm" data-act="rp-add">${svgSym('plus')}</button><button class="b sm dng" data-act="rp-del">${svgSym('close')}</button></div>
<div class="row"><select data-b="rp.method" style="width:110px">${['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map(m => `<option ${t.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select><input class="grow" data-b="rp.url" value="${esc(t.url)}" placeholder="https://..."></div>
<label>Header</label><textarea data-b="rp.headers" placeholder="Content-Type: application/json">${esc(t.headers)}</textarea>
<label>Govde</label><textarea data-b="rp.body">${esc(t.body)}</textarea>
<div class="row"><select data-b="rp.cred" class="grow"><option value="same-origin" ${t.cred === 'same-origin' ? 'selected' : ''}>cerez: same-origin</option><option value="include" ${t.cred === 'include' ? 'selected' : ''}>cerez: include</option><option value="omit" ${t.cred === 'omit' ? 'selected' : ''}>cerez: yok</option></select><select data-b="rp.redirect" class="grow"><option value="follow" ${t.redirect === 'follow' ? 'selected' : ''}>yonlendirme: takip</option><option value="manual" ${t.redirect === 'manual' ? 'selected' : ''}>yonlendirme: manuel</option></select></div>
<div class="row"><button class="b pri" data-act="rp-send">Gonder</button><button class="b" data-act="rp-load">Secili istegi yukle</button><button class="b" data-act="rp-dup">Cogalt</button><button class="b" data-act="rp-to-in">${svgSym('arrow')} Intruder</button></div>${respHTML}</div>`;
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
  'Yaygin yollar': () => ['admin', 'login', 'api', 'api/v1', 'config', 'backup', '.git/HEAD', '.env', 'robots.txt', 'sitemap.xml', 'swagger.json', 'openapi.json', 'graphql', 'debug', 'test', 'dashboard', 'user', 'users', 'health', 'status', 'metrics'].join('\n'),
  'Ozel karakterler': () => ['\'', '"', '<', '>', '{{7*7}}', '${7*7}', '../', '%00', '%0d%0a', ';', '|', '`', '\\', 'null', 'true', '-1', '0', '99999999999'].join('\n'),
  'Bos / uzun': () => ['', ' ', 'A'.repeat(256), 'A'.repeat(4096)].join('\n')
};
function renderIntruder() {
  const T = S.in, res = T.results.slice();
  const lens = {}; res.forEach(r => { lens[r.len] = (lens[r.len] || 0) + 1; });
  const mode = +Object.keys(lens).sort((a, b) => lens[b] - lens[a])[0];
  const sorters = { n: (a, b) => a.n - b.n, status: (a, b) => String(a.status).localeCompare(String(b.status)), len: (a, b) => b.len - a.len, ms: (a, b) => b.ms - a.ms };
  res.sort(sorters[T.sort] || sorters.n);
  const sel = res.find(r => r.n === T.sel);
  return `<div class="pad"><p class="hint">Yalnizca yetkili oldugun sistemlerde kullan. Degistirilecek yerleri <b>§deger§</b> ile isaretle.</p>
<div class="row"><select data-b="in.method" style="width:110px">${['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map(m => `<option ${T.method === m ? 'selected' : ''}>${m}</option>`).join('')}</select><input class="grow" data-b="in.url" value="${esc(T.url)}" placeholder="https://site/api/user/§1§"></div>
<label>Header</label><textarea data-b="in.headers">${esc(T.headers)}</textarea><label>Govde</label><textarea data-b="in.body">${esc(T.body)}</textarea>
<label>Payload listesi</label><textarea data-b="in.payloads" style="min-height:90px">${esc(T.payloads)}</textarea>
<div class="chips">${Object.keys(PRESETS).map(k => `<button class="b sm" data-act="in-preset" data-k="${esc(k)}">${esc(k)}</button>`).join('')}</div>
<div class="row"><select data-b="in.type" class="grow"><option value="sniper" ${T.type === 'sniper' ? 'selected' : ''}>Sniper</option><option value="ram" ${T.type === 'ram' ? 'selected' : ''}>Battering ram</option></select><input type="number" min="0" data-b="in.delay" value="${T.delay}" style="width:96px" placeholder="ms"><input type="number" min="1" max="6" data-b="in.conc" value="${T.conc}" style="width:80px"></div>
<div class="row"><button class="b ${T.running ? 'dng' : 'pri'}" data-act="in-run">${T.running ? 'Durdur' : 'Saldiriyi baslat'}</button><button class="b" data-act="in-clear">Sonuclari temizle</button><select data-b="in.sort" style="width:130px"><option value="n" ${T.sort === 'n' ? 'selected' : ''}>sira</option><option value="status" ${T.sort === 'status' ? 'selected' : ''}>durum</option><option value="len" ${T.sort === 'len' ? 'selected' : ''}>uzunluk</option><option value="ms" ${T.sort === 'ms' ? 'selected' : ''}>sure</option></select></div>
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
<div class="row"><button class="b" data-act="dec-move">Ciktiyi girise tasi</button><button class="b" data-act="dec-copy">Kopyala</button><button class="b" data-act="dec-cmp">Karsilastir A</button></div></div>`;
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
const stList = () => { const o = []; ['localStorage', 'sessionStorage'].forEach(a => { try { const s = W[a]; for (let i = 0; i < s.length; i++) { const k = s.key(i); if (k.indexOf('ip4:') === 0) continue; o.push({ a, k, v: s.getItem(k) }); } } catch (e) {} }); return o; };
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
const maskv = v => S.set.mask && v.length > 12 ? v.slice(0, 6) + '...' + v.slice(-3) : v;
function pgSecrets() {
  const r = S._res.secrets;
  return `<div class="row"><button class="b pri" data-act="scan-secrets">${r ? 'Yeniden tara' : 'Tara'}</button><span class="mut">Sayfa ve JS dosyalarinda anahtar/token desenleri</span></div>${r ? (r.length ? `<table>${r.slice(0, 300).map(([n, v]) => `<tr><td>${esc(n)}</td><td>${esc(limit(maskv(v), 120))}</td></tr>`).join('')}</table>` : '<div class="empty">Bir sey bulunamadi.</div>') : ''}`;
}
function pgConsole() {
  return `<div id="cons-log" style="max-height:34vh;overflow:auto;margin-bottom:8px"></div><textarea class="wrap" data-b="cons.code" id="cons-code" placeholder="JavaScript... (await destekli, $0 = secili oge)" style="min-height:64px"></textarea><div class="row"><button class="b pri" data-act="cons-run">Calistir</button><button class="b" data-act="cons-clear">Temizle</button></div>`;
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

/* ---------- KURALLAR ---------- */
S._nr = { target: 'req-header', match: '', replace: '', regex: false };
function renderRules() {
  const T = { 'req-url': 'Istek URL', 'req-header': 'Istek header', 'req-body': 'Istek govde', 'res-body': 'Yanit govde (fetch)' };
  return `<div class="pad"><h4 style="margin:0 0 4px">Match &amp; Replace</h4><p class="hint">Istek giderken veya yanit donerken otomatik degistirir.</p>
${S.rules.map((r, i) => `<div class="row"><label class="ck grow" style="margin:0"><input type="checkbox" data-act="rule-on" data-i="${i}" ${r.on ? 'checked' : ''}><span>${esc(T[r.target])}: <code>${esc(limit(r.match, 40))}</code> -&gt; <code>${esc(limit(r.replace, 40))}</code>${r.regex ? ' (regex)' : ''}</span></label><button class="b sm dng" data-act="rule-del" data-i="${i}">Sil</button></div>`).join('') || '<div class="empty">Kural yok.</div>'}
<label>Yeni kural</label><select data-b="nr.target">${Object.keys(T).map(k => `<option value="${k}" ${S._nr.target === k ? 'selected' : ''}>${T[k]}</option>`).join('')}</select>
<input data-b="nr.match" placeholder="Aranan" value="${esc(S._nr.match)}" style="margin-top:6px"><input data-b="nr.replace" placeholder="Yerine" value="${esc(S._nr.replace)}" style="margin-top:6px">
<label class="ck"><input type="checkbox" data-b="nr.regex" ${S._nr.regex ? 'checked' : ''}>Regex</label><div class="row"><button class="b pri" data-act="rule-add">Kural ekle</button></div>
<h4 style="margin:18px 0 4px">Script Lab</h4><p class="hint"><code>request</code> = {method,url,headers,body}; after'da <code>response.body</code> degistirilebilir (fetch).</p>
<label>Before Request</label><textarea data-b="sc.before" style="min-height:100px" placeholder="request.headers['X-Test']='1';">${esc(S.scripts.before)}</textarea>
<label>After Response</label><textarea data-b="sc.after" style="min-height:100px" placeholder="response.body = response.body.replace('a','b');">${esc(S.scripts.after)}</textarea></div>`;
}

/* ---------- KILAVUZ ---------- */
function renderGuide() {
  return `<div class="pad">
<div class="card"><h4>Istek, Yanit ve WebSocket Mudahale</h4><p class="hint">Mudahale sekmesinden HTTP isteklerini, sunucudan donen yanitlari (durum kodu, header, govde) ve WebSocket frame'lerini durdurup duzenleyebilir, iletebilir veya dusurebilirsin.</p></div>
<div class="card"><h4>Repeater ve Intruder</h4><p class="hint">Repeater ile tek istegi duzenleyip tekrar gonderebilir; Intruder ile <code>§deger§</code> alanlara liste halinde payload gondererek farklari analiz edebilirsin.</p></div>
<div class="card"><h4>Menu Boyutu ve Ikonlar</h4><p class="hint">Ayarlar sekmesinden panel boyutunu ve ikon CSS adresini ayarlayabilir; masaustunde panelin sag alt kosesinden surukleyerek genislik/yukseklik verebilirsin.</p></div>
</div>`;
}

/* ---------- AYARLAR ---------- */
function renderSettings() {
  const s = S.set;
  return `<div class="pad"><label class="ck"><input type="checkbox" data-b="set.mask" ${s.mask ? 'checked' : ''}>Hassas header'lari maskele</label>
<label class="ck"><input type="checkbox" data-b="set.bodies" ${s.bodies ? 'checked' : ''}>Istek / yanit govdesini yakala</label>
<label class="ck"><input type="checkbox" data-b="set.pretty" ${s.pretty ? 'checked' : ''}>JSON'u guzellestir</label>
<label class="ck"><input type="checkbox" data-b="set.outside" ${s.outside ? 'checked' : ''}>Panel disina dokununca kucult</label>
${EXT ? `<label class="ck"><input type="checkbox" data-b="set.persist" ${s.persist ? 'checked' : ''}>Sayfa gezinirken kayitlari sakla</label><label class="ck"><input type="checkbox" data-b="set.startOpen" ${s.startOpen ? 'checked' : ''}>Sayfa acilinca paneli ac</label>` : ''}
<label>Menu Boyut Sablonu</label>
<select data-b="set.panelSizePreset">
  <option value="compact" ${s.panelSizePreset === 'compact' ? 'selected' : ''}>Kompakt (420x500)</option>
  <option value="standard" ${s.panelSizePreset === 'standard' ? 'selected' : ''}>Standart (560x680)</option>
  <option value="wide" ${s.panelSizePreset === 'wide' ? 'selected' : ''}>Genis (780x740)</option>
  <option value="custom" ${s.panelSizePreset === 'custom' ? 'selected' : ''}>Ozel Boyut</option>
</select>
<div class="row">
  <div class="grow"><label>Genislik (px)</label><input type="number" min="320" max="1600" data-b="set.panelW" value="${s.panelW}"></div>
  <div class="grow"><label>Yukseklik (px)</label><input type="number" min="280" max="1200" data-b="set.panelH" value="${s.panelH}"></div>
</div>
<label>Harici Ikon CSS URL</label><input data-b="set.iconUrl" value="${esc(s.iconUrl || '')}" placeholder="https://...">
<label>Tema</label><select data-b="set.theme">${[['auto', 'Otomatik'], ['dark', 'Koyu'], ['light', 'Acik']].map(([k, l]) => `<option value="${k}" ${s.theme === k ? 'selected' : ''}>${l}</option>`).join('')}</select>
<label>Yazi boyutu (px)</label><input type="number" min="10" max="20" data-b="set.font" value="${s.font}">
<label>Maksimum kayit</label><input type="number" min="50" max="5000" data-b="set.max" value="${s.max}">
<label>Mudahalede otomatik ilet (sn, 0 = kapali)</label><input type="number" min="0" max="600" data-b="set.icTimeout" value="${s.icTimeout}">
<h4 style="margin:16px 0 4px">Canli dashboard (ayri sekme)</h4><div class="row"><button class="b ${S.tabMode ? 'on' : ''}" data-act="tabmode">Sekme modu: ${S.tabMode ? 'ACIK' : 'KAPALI'}</button><button class="b" data-act="opentab">Dashboard ac</button></div>
<div class="row" style="margin-top:14px"><button class="b" data-act="clear">Kayitlari temizle</button><button class="b dng" data-act="destroy">Inspector'i kaldir</button></div>
<p class="hint">Inspector Pro ${VER}${EXT ? ' · eklenti' : ' · yer imi'}</p></div>`;
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
const icItem = () => S.held.find(x => x.id === S.icSel) || S.held[0];
const resItem = () => S.resHeld.find(x => x.id === S.resSel) || S.resHeld[0];
const wsItem = () => S.wsHeld.find(x => x.id === S.wsSel) || S.wsHeld[0];

function setBound(n, v) {
  const [g, k] = n.split('.');
  if (n === 'note') { const r = selRec(); if (r) r.note = v; return; }
  if (g === 'ic') { if (k === 'filter') { S.icFilter = v; return; } const i = icItem(); if (!i) return; if (k === 'hdr') i.hdr = v; else i.req[k] = v; return; }
  if (g === 'res') { if (k === 'filter') { S.resIcFilter = v; return; } const i = resItem(); if (i) i[k] = v; return; }
  if (g === 'ws') { if (k === 'dir') S.wsIcDir = v; else if (k === 'filter') S.wsIcFilter = v; else if (k === 'data') { const i = wsItem(); if (i) i.data = v; } return; }
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
    if (k === 'max') { S.set.max = Math.max(50, Math.min(5000, v || 500)); while (S.requests.length > S.set.max) S.byId.delete(S.requests.pop().id); }
    if (k === 'font') S.set.font = Math.max(10, Math.min(20, v || 13));
    if (k === 'iconUrl') loadRemoteIcons(v);
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
  if (t.dataset.act === 'ic-step') { S.icStepMode = t.checked; return; }
  if (t.dataset.b && (t.tagName === 'SELECT' || t.type === 'checkbox')) {
    onInput(e);
    if (t.dataset.b === 'set.panelSizePreset' && S.open && S.tab === 'settings') renderTab();
  }
}
async function onClick(e) {
  const t = e.target; if (!(t instanceof Element)) return;
  const tabB = t.closest('[data-tab]'); if (tabB) { S.tab = tabB.dataset.tab; renderTabs(); renderTab(); return; }
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
      case 'to-rp': if (r) { rpNew(r); S.tab = 'repeater'; renderTabs(); renderTab(); } break;
      case 'to-in': if (r) { Object.assign(S.in, { method: r.method, url: r.url, headers: hdrText(r.requestHeaders), body: r.requestBody }); S.tab = 'intruder'; renderTabs(); renderTab(); toast('§ ile isaretle'); } break;
      /* istek mudahale */
      case 'ic-toggle': S.icOn = !S.icOn; if (!S.icOn) S.held.slice().forEach(h => release(h, 'forward')); renderTab(); badges(); break;
      case 'ic-pick': S.icSel = el.dataset.id; renderTab(); break;
      case 'ic-fwd': { const h = icItem(); if (h) release(h, 'forward'); break; }
      case 'ic-drop': { const h = icItem(); if (h) release(h, 'drop'); break; }
      case 'ic-fwdall': S.held.slice().forEach(h => release(h, 'forward')); break;
      case 'ic-dropall': S.held.slice().forEach(h => release(h, 'drop')); break;
      case 'ic-rp': { const h = icItem(); if (h) { rpNew({ method: h.req.method, url: h.req.url, requestHeaders: parseHdr(h.hdr), requestBody: h.req.body }); S.tab = 'repeater'; renderTabs(); renderTab(); } break; }
      /* yanit mudahale */
      case 'res-toggle': S.resIcOn = !S.resIcOn; if (!S.resIcOn) S.resHeld.slice().forEach(h => resRelease(h, 'forward')); renderTab(); badges(); break;
      case 'res-pick': S.resSel = el.dataset.id; renderTab(); break;
      case 'res-fwd': { const h = resItem(); if (h) resRelease(h, 'forward'); break; }
      case 'res-drop': { const h = resItem(); if (h) resRelease(h, 'drop'); break; }
      case 'res-fwdall': S.resHeld.slice().forEach(h => resRelease(h, 'forward')); break;
      case 'res-dropall': S.resHeld.slice().forEach(h => resRelease(h, 'drop')); break;
      /* ws mudahale */
      case 'ws-toggle': S.wsIcOn = !S.wsIcOn; if (!S.wsIcOn) S.wsHeld.slice().forEach(h => wsRelease(h, 'forward')); renderTab(); badges(); break;
      case 'ws-pick': S.wsSel = el.dataset.id; renderTab(); break;
      case 'ws-fwd': { const h = wsItem(); if (h) wsRelease(h, 'forward'); break; }
      case 'ws-drop': { const h = wsItem(); if (h) wsRelease(h, 'drop'); break; }
      case 'ws-fwdall': S.wsHeld.slice().forEach(h => wsRelease(h, 'forward')); break;
      case 'ws-dropall': S.wsHeld.slice().forEach(h => wsRelease(h, 'drop')); break;
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
      /* intruder / decoder / compare / target / page / rules */
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
    if (Math.abs(rw - (Number(S.set.panelW) || 560)) > 6 || Math.abs(rh - (Number(S.set.panelH) || 680)) > 6) {
      S.set.panelW = rw; S.set.panelH = rh; S.set.panelSizePreset = 'custom'; LS.set('set', S.set);
    }
  }
  panel.classList.toggle('wide', r.width >= 640);
  panel.classList.toggle('narrow', r.width < 640);
}).observe(panel);
if (W.matchMedia) { try { W.matchMedia('(prefers-color-scheme: light)').addEventListener('change', applyTheme); } catch (e) {} }

function persistSave() {
  if (!EXT || !S.set.persist) return;
  try { W.sessionStorage.setItem('ip4:hist', JSON.stringify(S.requests.slice(0, 150).map(r => Object.assign({}, r, { responseBody: limit(r.responseBody, 5000), requestBody: limit(r.requestBody, 5000), frames: undefined })))); } catch (e) {}
}
function persistLoad() {
  if (!EXT) return;
  try { const a = JSON.parse(W.sessionStorage.getItem('ip4:hist') || '[]'); a.reverse().forEach(r => { r.restored = true; r.id = r.id || uid(); addRecord(r); }); } catch (e) {}
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
    addRecord({ type: 'net', method: x.method, url: x.url, status: x.status == null ? 'pending' : x.status, statusText: x.statusText || '', requestHeaders: x.requestHeaders || {}, responseHeaders: x.responseHeaders || {}, duration: x.duration || 0, mime: x.mime || '', size: x.size || 0, time: x.time || Date.now(), netType: x.type, ip: x.ip, fromCache: x.fromCache, error: x.error });
  }
}
if (EXT) { W.addEventListener('message', onBridge); W.addEventListener('pagehide', persistSave); W.postMessage({ __ipc: 'hello' }, '*'); }

const api = {
  show: openPanel, hide: closePanel, toggle: togglePanel, openTab: openDashboard,
  enableTabMode() { setTabMode(true); }, disableTabMode() { setTabMode(false); },
  clear() { S.requests = []; S.byId.clear(); S.selected = null; badges(); publish(); if (S.open) renderTab(); },
  exportHAR() { download('inspector-pro.har', JSON.stringify(toHAR(S.requests), null, 2)); },
  manualSend: o => sendRaw(o, 'manual'),
  destroy() {
    S.on = false; setTabMode(false);
    if (nativeFetch) W.fetch = nativeFetch;
    XHR.prototype.open = xhrOpen; XHR.prototype.send = xhrSend; XHR.prototype.setRequestHeader = xhrHeader;
    if (NativeWS) W.WebSocket = NativeWS; if (nativeBeacon) navigator.sendBeacon = nativeBeacon;
    ['log', 'info', 'warn', 'error', 'debug'].forEach(k => { console[k] = nativeConsole[k]; });
    host.remove(); delete W.__inspectorPro;
  },
  state: S
};
W.__inspectorPro = api;

function mount() {
  if (!host.isConnected) (D.documentElement || D).appendChild(host);
  loadRemoteIcons(S.set.iconUrl);
  applyTheme(); fitViewport(); badges();
}
mount(); persistLoad();
if (D.readyState === 'loading') D.addEventListener('DOMContentLoaded', mount);
if (!EXT) openPanel();
})();
