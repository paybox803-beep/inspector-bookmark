
(() => {
'use strict';

/* =========================================
   INSPECTOR PRO
   Single-file browser traffic inspector
========================================= */

if (window.__inspectorPro?.destroy) {
  window.__inspectorPro.show();
  return;
}

const W = window;
const D = document;
const STATE = {
  active: true,
  intercept: false,
  tabMode: false,
  fullscreen: false,
  requests: [],
  selected: null,
  filter: '',
  tab: 'traffic',
  maxRecords: 500,
  dashboard: null,
  channel: null,
  sequence: 0,
  scripts: {
    before: '',
    after: ''
  },
  settings: {
    maskSensitive: true,
    captureBodies: true,
    maxBody: 150000
  }
};

const nativeFetch = W.fetch.bind(W);
const NativeXHR = W.XMLHttpRequest;
const originalOpen = NativeXHR.prototype.open;
const originalSend = NativeXHR.prototype.send;
const originalSetHeader = NativeXHR.prototype.setRequestHeader;

const SENSITIVE = /authorization|cookie|token|secret|password|api[-_]?key/i;

const uid = () =>
  Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

const safeString = value => {
  try {
    if (typeof value === 'string') return value;
    if (value == null) return '';
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
};

const truncate = (value, max = STATE.settings.maxBody) => {
  const str = String(value ?? '');
  return str.length > max
    ? str.slice(0, max) + '\n...[truncated]'
    : str;
};

const maskHeaders = headers => {
  const result = {};
  try {
    const entries = headers instanceof Headers
      ? [...headers.entries()]
      : Object.entries(headers || {});
    for (const [key, value] of entries) {
      result[key] = STATE.settings.maskSensitive && SENSITIVE.test(key)
        ? '[REDACTED]'
        : String(value);
    }
  } catch {}
  return result;
};

const parseHeaders = raw => {
  const result = {};
  String(raw || '').trim().split(/\r?\n/).forEach(line => {
    const i = line.indexOf(':');
    if (i > 0) result[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return result;
};

function publish(type = 'TRAFFIC_UPDATE') {
  if (!STATE.tabMode || !STATE.channel) return;

  const snapshot = {
    type,
    sequence: ++STATE.sequence,
    timestamp: Date.now(),
    data: {
      requests: STATE.requests,
      selected: STATE.selected,
      active: STATE.active,
      intercept: STATE.intercept,
      tab: STATE.tab
    }
  };

  try {
    STATE.channel.postMessage({
      source: 'inspector-main',
      ...snapshot
    });
  } catch (e) {
    console.warn('Inspector live publish failed', e);
  }
}

function notify() {
  render();
  publish();
}

function addRecord(record) {
  record.id ||= uid();
  record.time ||= Date.now();
  record.status ||= 'pending';
  record.duration ||= 0;
  record.requestHeaders ||= {};
  record.responseHeaders ||= {};
  record.requestBody ??= '';
  record.responseBody ??= '';

  STATE.requests.unshift(record);
  if (STATE.requests.length > STATE.maxRecords) {
    STATE.requests.length = STATE.maxRecords;
  }

  STATE.selected = record.id;
  notify();
  return record;
}

function updateRecord(id, updates) {
  const item = STATE.requests.find(x => x.id === id);
  if (!item) return;
  Object.assign(item, updates);
  notify();
}

function selectedRecord() {
  return STATE.requests.find(x => x.id === STATE.selected) || null;
}

function runHook(code, context) {
  if (!code.trim()) return context;

  try {
    const fn = new Function(
      'request',
      'response',
      '"use strict";\n' + code + '\n;return {request,response};'
    );
    const result = fn(context.request, context.response);
    return result || context;
  } catch (e) {
    context.error = String(e);
    return context;
  }
}

/* =========================================
   FETCH INTERCEPTION
========================================= */

W.fetch = async function(input, init = {}) {
  if (!STATE.active) return nativeFetch(input, init);

  const started = performance.now();
  const request = input instanceof Request
    ? input
    : new Request(input, init);

  const id = uid();
  let requestBody = '';

  try {
    if (STATE.settings.captureBodies && request.method !== 'GET') {
      requestBody = await request.clone().text();
    }
  } catch {}

  const headers = maskHeaders(request.headers);

  const record = addRecord({
    id,
    type: 'fetch',
    method: request.method,
    url: request.url,
    requestHeaders: headers,
    requestBody: truncate(requestBody),
    responseHeaders: {},
    responseBody: '',
    status: 'pending',
    startedAt: Date.now()
  });

  let req = request;

  try {
    const hook = runHook(STATE.scripts.before, {
      request: {
        url: request.url,
        method: request.method,
        headers: { ...headers },
        body: requestBody
      },
      response: null
    });

    if (hook.request) {
      req = new Request(hook.request.url || request.url, {
        method: hook.request.method || request.method,
        headers: hook.request.headers || headers,
        body: ['GET', 'HEAD'].includes(
          (hook.request.method || request.method).toUpperCase()
        ) ? undefined : hook.request.body,
        credentials: request.credentials,
        mode: request.mode,
        redirect: request.redirect
      });
    }

    const response = await nativeFetch(req);
    let body = '';

    try {
      if (STATE.settings.captureBodies) {
        body = await response.clone().text();
      }
    } catch {}

    const duration = Math.round(performance.now() - started);

    updateRecord(id, {
      status: response.status,
      statusText: response.statusText,
      ok: response.ok,
      duration,
      responseHeaders: maskHeaders(response.headers),
      responseBody: truncate(body),
      finishedAt: Date.now()
    });

    return response;
  } catch (error) {
    updateRecord(id, {
      status: 'error',
      error: String(error),
      duration: Math.round(performance.now() - started),
      finishedAt: Date.now()
    });
    throw error;
  }
};

/* =========================================
   XHR INTERCEPTION
========================================= */

const xhrMeta = new WeakMap();

NativeXHR.prototype.open = function(method, url, async = true, user, password) {
  xhrMeta.set(this, {
    method: String(method || 'GET').toUpperCase(),
    url: String(url),
    async,
    headers: {},
    body: '',
    started: 0,
    id: uid()
  });

  return originalOpen.call(this, method, url, async, user, password);
};

NativeXHR.prototype.setRequestHeader = function(name, value) {
  const meta = xhrMeta.get(this);
  if (meta) meta.headers[name] = value;
  return originalSetHeader.call(this, name, value);
};

NativeXHR.prototype.send = function(body) {
  const meta = xhrMeta.get(this);
  if (!meta || !STATE.active) return originalSend.call(this, body);

  meta.started = performance.now();
  meta.body = truncate(safeString(body));

  const record = addRecord({
    id: meta.id,
    type: 'xhr',
    method: meta.method,
    url: meta.url,
    requestHeaders: maskHeaders(meta.headers),
    requestBody: meta.body,
    responseHeaders: {},
    responseBody: '',
    status: 'pending'
  });

  this.addEventListener('loadend', () => {
    let responseBody = '';

    try {
      if (STATE.settings.captureBodies) {
        responseBody = typeof this.responseText === 'string'
          ? this.responseText
          : safeString(this.response);
      }
    } catch {}

    let responseHeaders = {};
    try {
      responseHeaders = maskHeaders(parseHeaders(this.getAllResponseHeaders()));
    } catch {}

    updateRecord(meta.id, {
      status: this.status || 'error',
      statusText: this.statusText,
      responseHeaders,
      responseBody: truncate(responseBody),
      duration: Math.round(performance.now() - meta.started),
      finishedAt: Date.now()
    });
  }, { once: true });

  return originalSend.call(this, body);
};

/* =========================================
   MANUAL REQUEST / REPEATER
========================================= */

async function manualSend(options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const url = String(options.url || '').trim();

  if (!url) throw new Error('URL gerekli.');

  const id = uid();
  const started = performance.now();

  const headers = {};
  String(options.headers || '').split(/\r?\n/).forEach(line => {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });

  const record = addRecord({
    id,
    type: 'manual',
    method,
    url,
    requestHeaders: maskHeaders(headers),
    requestBody: truncate(options.body || ''),
    responseHeaders: {},
    responseBody: '',
    status: 'sending'
  });

  try {
    const response = await nativeFetch(url, {
      method,
      headers,
      body: ['GET', 'HEAD'].includes(method) ? undefined : options.body,
      credentials: 'same-origin'
    });

    let body = '';
    try {
      if (STATE.settings.captureBodies) body = await response.clone().text();
    } catch {}

    updateRecord(id, {
      status: response.status,
      statusText: response.statusText,
      responseHeaders: maskHeaders(response.headers),
      responseBody: truncate(body),
      duration: Math.round(performance.now() - started),
      finishedAt: Date.now()
    });

    return response;
  } catch (error) {
    updateRecord(id, {
      status: 'error',
      error: String(error),
      duration: Math.round(performance.now() - started)
    });
    throw error;
  }
}

/* =========================================
   EXPORTS
========================================= */

function downloadFile(filename, content, type = 'application/json') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = D.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportHAR() {
  const entries = STATE.requests.map(r => ({
    startedDateTime: new Date(r.time).toISOString(),
    time: r.duration || 0,
    request: {
      method: r.method,
      url: r.url,
      httpVersion: 'HTTP/1.1',
      headers: Object.entries(maskHeaders(r.requestHeaders))
        .map(([name, value]) => ({ name, value })),
      queryString: [],
      headersSize: -1,
      bodySize: r.requestBody?.length || 0,
      postData: r.requestBody
        ? { mimeType: 'text/plain', text: r.requestBody }
        : undefined
    },
    response: {
      status: Number(r.status) || 0,
      statusText: r.statusText || '',
      httpVersion: 'HTTP/1.1',
      headers: Object.entries(maskHeaders(r.responseHeaders))
        .map(([name, value]) => ({ name, value })),
      content: {
        size: r.responseBody?.length || 0,
        mimeType: 'text/plain',
        text: r.responseBody || ''
      },
      headersSize: -1,
      bodySize: r.responseBody?.length || 0
    },
    cache: {},
    timings: { send: 0, wait: r.duration || 0, receive: 0 }
  }));

  downloadFile('inspector-pro.har', JSON.stringify({
    log: {
      version: '1.2',
      creator: { name: 'Inspector Pro', version: '2.0' },
      entries
    }
  }, null, 2));
}

function makeCurl(r) {
  const parts = ['curl', '-X', r.method || 'GET'];

  parts.push("'" + String(r.url || '').replace(/'/g, "'\\''") + "'");

  for (const [key, value] of Object.entries(maskHeaders(r.requestHeaders))) {
    parts.push('-H');
    parts.push("'" + key + ': ' + value + "'");
  }

  if (r.requestBody) {
    parts.push('--data-raw');
    parts.push("'" + String(r.requestBody).replace(/'/g, "'\\''") + "'");
  }

  return parts.join(' ');
}

function copyText(value) {
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(value).catch(() => fallbackCopy(value));
  } else {
    fallbackCopy(value);
  }
}

function fallbackCopy(value) {
  const el = D.createElement('textarea');
  el.value = value;
  D.body.appendChild(el);
  el.select();
  D.execCommand('copy');
  el.remove();
}

/* =========================================
   UI STYLES
========================================= */

const style = D.createElement('style');
style.textContent = `
#mini-burp{
 position:fixed;z-index:2147483646;right:12px;bottom:12px;
 width:min(900px,calc(100vw - 24px));height:min(690px,calc(100vh - 24px));
 background:#111722;color:#e8eef8;border:1px solid #354258;
 border-radius:13px;box-shadow:0 12px 50px #0009;
 display:flex;flex-direction:column;overflow:hidden;
 font:13px/1.4 system-ui,Arial,sans-serif;
}
#mini-burp *{box-sizing:border-box}
#mini-burp .top{
 display:flex;align-items:center;gap:8px;padding:10px;
 background:#1b2637;flex-wrap:wrap
}
#mini-burp button,#mini-burp input,#mini-burp select,#mini-burp textarea{
 font:inherit
}
#mini-burp button{
 color:#e8eef8;background:#2b3a52;border:1px solid #43536c;
 border-radius:7px;padding:7px 10px;cursor:pointer
}
#mini-burp button:hover{background:#3b4d69}
#mini-burp button.active{background:#176b55}
#mini-burp .brand{font-weight:800;margin-right:auto}
#mini-burp .tabs{display:flex;gap:5px;padding:8px;overflow:auto}
#mini-burp .layout{display:grid;grid-template-columns: minmax(220px,35%) 1fr;min-height:0;flex:1}
#mini-burp .list{overflow:auto;border-right:1px solid #344157}
#mini-burp .details{overflow:auto;padding:10px;min-width:0}
#mini-burp .item{padding:10px;border-bottom:1px solid #273448;cursor:pointer;overflow-wrap:anywhere}
#mini-burp .item.selected{background:#263750}
#mini-burp .muted{color:#9eacc1}
#mini-burp .field{margin:8px 0}
#mini-burp label{display:block;color:#aebbd0;margin-bottom:4px}
#mini-burp input,#mini-burp textarea,#mini-burp select{
 width:100%;background:#0b111b;color:#edf2fa;border:1px solid #39475e;
 border-radius:7px;padding:9px;min-width:0
}
#mini-burp textarea{min-height:90px;resize:vertical}
#mini-burp pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b111b;padding:10px;border-radius:7px;max-height:300px;overflow:auto}
#mini-burp .toolbar{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}
#mini-burp .hidden{display:none!important}
#mini-burp .bottom{padding:7px 10px;background:#1b2637;color:#aab7c9}
#mini-burp:fullscreen{width:100vw;height:100vh;inset:0;border:0;border-radius:0}
#mini-burp .mobile-nav{display:none}
@media(max-width:650px){
 #mini-burp{right:0;bottom:0;width:100vw;height:92dvh;border-radius:13px 13px 0 0}
 #mini-burp .layout{grid-template-columns:1fr}
 #mini-burp .list{border-right:0;max-height:38%;border-bottom:1px solid #344157}
 #mini-burp .details{min-height:0}
 #mini-burp .top{gap:5px;padding:7px}
 #mini-burp .top button{padding:7px}
 #mini-burp .tabs{display:none}
 #mini-burp .mobile-nav{display:flex;gap:4px;overflow:auto;padding:6px}
 #mini-burp .mobile-nav button{flex:1;white-space:nowrap}
}
`;
D.head.appendChild(style);

/* =========================================
   BUILD PANEL
========================================= */

const root = D.createElement('section');
root.id = 'mini-burp';
root.innerHTML = `
 <div class="top">
  <span class="brand">Inspector Pro</span>
  <button data-action="pause">Pause</button>
  <button data-action="tabmode">Sekme Modu</button>
  <button data-action="opentab">Yan Sekme</button>
  <button data-action="fullscreen">Tam Ekran</button>
  <button data-action="hide">×</button>
 </div>
 <div class="tabs">
  <button data-tab="traffic">Traffic</button>
  <button data-tab="repeater">Repeater</button>
  <button data-tab="scripts">Script Lab</button>
  <button data-tab="settings">Ayarlar</button>
 </div>
 <div class="mobile-nav">
  <button data-tab="traffic">Traffic</button>
  <button data-tab="repeater">Repeater</button>
  <button data-tab="scripts">Scripts</button>
  <button data-tab="settings">Ayarlar</button>
 </div>
 <div id="ip-content" style="display:flex;flex:1;min-height:0;flex-direction:column"></div>
 <div class="bottom" id="ip-status">Hazır · Fetch + XHR</div>
`;
D.body.appendChild(root);

function el(selector) {
  return root.querySelector(selector);
}

function button(label, action, extra = '') {
  return `<button data-action="${action}" ${extra}>${label}</button>`;
}

function renderTraffic() {
  const query = STATE.filter.toLowerCase();
  const list = STATE.requests.filter(r =>
    [r.url, r.method, r.status, r.type]
      .join(' ').toLowerCase().includes(query)
  );

  const selected = selectedRecord();

  return `
   <div class="field" style="padding:8px">
    <input id="ip-search" placeholder="URL, method veya status ara..." value="${escapeHTML(STATE.filter)}">
    <div class="toolbar">
     ${button('HAR dışa aktar','har')}
     ${button('Temizle','clear')}
     ${button('Ham istek','rawrequest')}
     ${button('cURL kopyala','curl')}
    </div>
   </div>
   <div class="layout">
    <div class="list">
     ${list.map(r => `
      <div class="item ${r.id === STATE.selected ? 'selected' : ''}" data-id="${r.id}">
       <strong>${escapeHTML(r.method)}</strong>
       <span class="muted">${escapeHTML(String(r.status))}</span>
       <div>${escapeHTML(r.url)}</div>
       <small class="muted">${escapeHTML(r.type)} · ${r.duration || 0} ms</small>
      </div>
     `).join('')}
    </div>
    <div class="details">
     ${selected ? renderRecord(selected) : '<p class="muted">Bir istek seç.</p>'}
    </div>
   </div>
  `;
}

function renderRecord(r) {
  return `
   <h3>${escapeHTML(r.method)} ${escapeHTML(r.url)}</h3>
   <p class="muted">Status: ${escapeHTML(String(r.status))} · Süre: ${r.duration || 0} ms</p>
   <div class="toolbar">
    ${button('cURL kopyala','curl')}
    ${button('Ham istek kopyala','rawrequest')}
    ${button('Ham yanıt kopyala','rawresponse')}
    ${button('Repeater’a gönder','to-repeater')}
   </div>
   <h4>Request Headers</h4><pre>${escapeHTML(safeString(r.requestHeaders))}</pre>
   <h4>Request Body</h4><pre>${escapeHTML(r.requestBody)}</pre>
   <h4>Response Headers</h4><pre>${escapeHTML(safeString(r.responseHeaders))}</pre>
   <h4>Response Body</h4><pre>${escapeHTML(r.responseBody)}</pre>
   ${r.error ? `<h4>Hata</h4><pre>${escapeHTML(r.error)}</pre>` : ''}
  `;
}

function renderRepeater() {
  const r = selectedRecord() || {};
  return `
   <div class="details">
    <h3>Repeater / Manuel İstek</h3>
    <div class="field"><label>Method</label>
     <select id="rp-method">
      ${['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'].map(m =>
        `<option ${r.method === m ? 'selected' : ''}>${m}</option>`).join('')}
     </select>
    </div>
    <div class="field"><label>URL</label>
     <input id="rp-url" value="${escapeHTML(r.url || '')}" placeholder="https://example.com/api">
    </div>
    <div class="field"><label>Headers (her satır bir header)</label>
     <textarea id="rp-headers">${escapeHTML(Object.entries(r.requestHeaders || {}).map(([k,v])=>k+': '+v).join('\n'))}</textarea>
    </div>
    <div class="field"><label>Body</label>
     <textarea id="rp-body">${escapeHTML(r.requestBody || '')}</textarea>
    </div>
    <div class="toolbar">
     ${button('Gönder','send')}
     ${button('Seçili isteği yükle','load-selected')}
    </div>
   </div>
  `;
}

function renderScripts() {
  return `
   <div class="details">
    <h3>Script Lab</h3>
    <p class="muted">Ön işleme scripti request nesnesini değiştirebilir. Yetkili olduğun test ortamlarında kullan.</p>
    <label>Before Request</label>
    <textarea id="ip-before" style="min-height:150px">${escapeHTML(STATE.scripts.before)}</textarea>
    <label>After Response</label>
    <textarea id="ip-after" style="min-height:150px">${escapeHTML(STATE.scripts.after)}</textarea>
    <div class="toolbar">${button('Scriptleri kaydet','save-scripts')}</div>
   </div>
  `;
}

function renderSettings() {
  return `
   <div class="details">
    <h3>Ayarlar</h3>
    <label><input type="checkbox" id="ip-mask" ${STATE.settings.maskSensitive ? 'checked' : ''}> Hassas header maskele</label>
    <label><input type="checkbox" id="ip-bodies" ${STATE.settings.captureBodies ? 'checked' : ''}> Body yakala</label>
    <div class="field"><label>Maksimum kayıt</label>
     <input id="ip-max" type="number" min="50" max="5000" value="${STATE.maxRecords}">
    </div>
    <div class="toolbar">
     ${button('Ayarları uygula','save-settings')}
     ${button('Sekme modunu kapat','disable-tab')}
    </div>
   </div>
  `;
}

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;',
    '"': '&quot;', "'": '&#39;'
  })[c]);
}

function render() {
  if (!root.isConnected) return;

  const content = el('#ip-content');

  if (STATE.tab === 'traffic') content.innerHTML = renderTraffic();
  else if (STATE.tab === 'repeater') content.innerHTML = renderRepeater();
  else if (STATE.tab === 'scripts') content.innerHTML = renderScripts();
  else if (STATE.tab === 'settings') content.innerHTML = renderSettings();

  el('#ip-status').textContent =
    `${STATE.requests.length} kayıt · ${STATE.tabMode ? 'Canlı sekme açık' : 'Sekme modu kapalı'}`;

  root.querySelectorAll('[data-tab]').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === STATE.tab);
  });
}

/* =========================================
   DASHBOARD TAB
========================================= */

function openDashboard() {
  if (!STATE.tabMode || !STATE.channel) {
    alert('Önce Sekme Modunu etkinleştir.');
    return;
  }

  if (STATE.dashboard && !STATE.dashboard.closed) {
    STATE.dashboard.focus();
    return;
  }

  const tab = W.open('', 'InspectorProDashboard');
  if (!tab) {
    alert('Yeni sekme açılamadı. Popup iznini kontrol et.');
    return;
  }

  STATE.dashboard = tab;

  tab.document.write(`<!doctype html>
  <html lang="tr">
  <head>
   <meta charset="utf-8">
   <meta name="viewport" content="width=device-width,initial-scale=1">
   <title>Inspector Pro Dashboard</title>
   <style>
    *{box-sizing:border-box}
    body{margin:0;background:#101722;color:#e8eef8;font:14px system-ui}
    header{position:sticky;top:0;background:#1d293b;padding:12px;
    display:flex;align-items:center;gap:8px;flex-wrap:wrap}
    button{background:#31435e;color:white;border:0;padding:9px;
    border-radius:7px;cursor:pointer}
    main{padding:12px}
    input,textarea,select{width:100%;background:#0a111c;color:white;
    border:1px solid #40516b;padding:9px;border-radius:7px}
    .layout{display:grid;grid-template-columns:35% 1fr;gap:10px}
    .list{overflow:auto;max-height:75vh}
    .item{padding:10px;border-bottom:1px solid #30405a;cursor:pointer}
    pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a111c;
    padding:10px;border-radius:7px;overflow:auto}
    .muted{color:#a6b5c9}
    @media(max-width:650px){.layout{grid-template-columns:1fr}.list{max-height:35vh}}
   </style>
  </head>
  <body>
   <header>
    <strong>Inspector Pro · Live</strong>
    <span id="connection">Bağlanıyor...</span>
    <button id="fullscreen">Tam Ekran</button>
   </header>
   <main id="app">Veri bekleniyor...</main>
   <script>
    const ch = new BroadcastChannel('inspector-pro-live-v2');
    const app = document.getElementById('app');
    const connection = document.getElementById('connection');
    let data = {};
    let selected = null;
    let tab = 'traffic';

    const esc = s => String(s ?? '').replace(/[&<>"']/g,c=>({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    })[c]);

    function render(){
      const requests = data.requests || [];
      const current = requests.find(r=>r.id===selected) || requests[0];

      app.innerHTML = \`
       <nav style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap">
        <button data-tab="traffic">Traffic</button>
        <button data-tab="repeater">Repeater</button>
        <button data-tab="settings">Ayarlar</button>
       </nav>
       \${tab==='traffic' ? \`
        <input id="search" placeholder="Ara...">
        <div class="layout">
         <div class="list" id="list">
          \${requests.map(r=>\`
           <div class="item" data-id="\${esc(r.id)}">
            <b>\${esc(r.method)}</b> \${esc(r.status)}
            <div>\${esc(r.url)}</div>
           </div>\`).join('')}
         </div>
         <div id="detail">
          \${current ? \`
           <h3>\${esc(current.method)} \${esc(current.url)}</h3>
           <p class="muted">Status \${esc(current.status)} · \${current.duration||0} ms</p>
           <h4>Request headers</h4><pre>\${esc(JSON.stringify(current.requestHeaders,null,2))}</pre>
           <h4>Request body</h4><pre>\${esc(current.requestBody)}</pre>
           <h4>Response headers</h4><pre>\${esc(JSON.stringify(current.responseHeaders,null,2))}</pre>
           <h4>Response body</h4><pre>\${esc(current.responseBody)}</pre>
           <button id="to-repeater">Repeater’a aktar</button>
          \` : 'İstek seçilmedi'}
         </div>
        </div>\` : tab==='repeater' ? \`
         <h3>Repeater</h3>
         <select id="method"><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select>
         <input id="url" placeholder="URL" value="\${esc(current?.url||'')}">
         <textarea id="headers" placeholder="Header: value"></textarea>
         <textarea id="body" placeholder="Request body"></textarea>
         <button id="send">Gönder</button>
       \` : \`
         <h3>Ayarlar</h3>
         <p>Canlı trafik bağlantısı açık.</p>
         <p>Toplam kayıt: \${requests.length}</p>
       \`}
      \`;

      app.querySelectorAll('[data-tab]').forEach(b=>{
        b.onclick=()=>{tab=b.dataset.tab;render()};
      });

      app.querySelectorAll('[data-id]').forEach(b=>{
        b.onclick=()=>{selected=b.dataset.id;render()};
      });

      const search=document.getElementById('search');
      if(search) search.oninput=()=>{
        const q=search.value.toLowerCase();
        app.querySelectorAll('[data-id]').forEach(item=>{
          item.style.display=item.textContent.toLowerCase().includes(q)?'':'none';
        });
      };

      const transfer=document.getElementById('to-repeater');
      if(transfer) transfer.onclick=()=>{
        tab='repeater';render();
      };

      const send=document.getElementById('send');
      if(send) send.onclick=()=>{
        ch.postMessage({
          source:'inspector-dashboard',
          type:'MANUAL_SEND',
          data:{
            method:document.getElementById('method').value,
            url:document.getElementById('url').value,
            headers:document.getElementById('headers').value,
            body:document.getElementById('body').value
          }
        });
      };
    }

    ch.onmessage=event=>{
      const msg=event.data;
      if(!msg || msg.source!=='inspector-main')return;
      connection.textContent='● Canlı bağlantı';
      if(msg.type==='SNAPSHOT'||msg.type==='TRAFFIC_UPDATE'){
        data=msg.data||{};
        if(!selected && data.selected) selected=data.selected;
        render();
      }
    };

    ch.postMessage({source:'inspector-dashboard',type:'DASHBOARD_READY'});
    ch.postMessage({source:'inspector-dashboard',type:'REQUEST_SNAPSHOT'});

    document.getElementById('fullscreen').onclick=async()=>{
      try{
        if(document.fullscreenElement) await document.exitFullscreen();
        else await document.documentElement.requestFullscreen();
      }catch{}
    };

    window.addEventListener('beforeunload',()=>{
      ch.postMessage({source:'inspector-dashboard',type:'DASHBOARD_CLOSED'});
      ch.close();
    });
   <\/script>
  </body>
  </html>`);

  tab.document.close();
}

/* =========================================
   EVENTS
========================================= */

root.addEventListener('click', async event => {
  const action = event.target.closest('[data-action]')?.dataset.action;
  const tab = event.target.closest('[data-tab]')?.dataset.tab;
  const item = event.target.closest('[data-id]');

  if (tab) {
    STATE.tab = tab;
    render();
    return;
  }

  if (item) {
    STATE.selected = item.dataset.id;
    render();
    publish();
    return;
  }

  if (!action) return;

  try {
    switch (action) {
      case 'pause':
        STATE.active = !STATE.active;
        event.target.textContent = STATE.active ? 'Pause' : 'Resume';
        notify();
        break;

      case 'tabmode':
        if (!STATE.tabMode) {
          STATE.channel = new BroadcastChannel('inspector-pro-live-v2');
          STATE.tabMode = true;

          STATE.channel.onmessage = async e => {
            const msg = e.data;
            if (!msg || msg.source !== 'inspector-dashboard') return;

            if (msg.type === 'REQUEST_SNAPSHOT' || msg.type === 'DASHBOARD_READY') {
              publish('SNAPSHOT');
            }

            if (msg.type === 'MANUAL_SEND') {
              try {
                await manualSend(msg.data);
              } catch (err) {
                console.error(err);
              }
            }

            if (msg.type === 'DASHBOARD_CLOSED') {
              STATE.dashboard = null;
            }
          };

          openDashboard();
          publish('SNAPSHOT');
        } else {
          STATE.tabMode = false;
          STATE.channel?.close();
          STATE.channel = null;
          if (STATE.dashboard && !STATE.dashboard.closed) STATE.dashboard.close();
          STATE.dashboard = null;
          render();
        }
        break;

      case 'opentab':
        openDashboard();
        break;

      case 'fullscreen':
        if (D.fullscreenElement === root) await D.exitFullscreen();
        else await root.requestFullscreen();
        break;

      case 'hide':
        root.classList.add('hidden');
        break;

      case 'har':
        exportHAR();
        break;

      case 'clear':
        STATE.requests = [];
        STATE.selected = null;
        notify();
        break;

      case 'curl': {
        const r = selectedRecord();
        if (r) copyText(makeCurl(r));
        break;
      }

      case 'rawrequest': {
        const r = selectedRecord();
        if (r) copyText(
          `${r.method} ${r.url}\n` +
          Object.entries(r.requestHeaders || {}).map(([k,v])=>`${k}: ${v}`).join('\n') +
          '\n\n' + (r.requestBody || '')
        );
        break;
      }

      case 'rawresponse': {
        const r = selectedRecord();
        if (r) copyText(
          `HTTP ${r.status} ${r.statusText || ''}\n` +
          Object.entries(r.responseHeaders || {}).map(([k,v])=>`${k}: ${v}`).join('\n') +
          '\n\n' + (r.responseBody || '')
        );
        break;
      }

      case 'to-repeater':
      case 'load-selected':
        STATE.tab = 'repeater';
        render();
        break;

      case 'send':
        await manualSend({
          method: el('#rp-method').value,
          url: el('#rp-url').value,
          headers: el('#rp-headers').value,
          body: el('#rp-body').value
        });
        break;

      case 'save-scripts':
        STATE.scripts.before = el('#ip-before').value;
        STATE.scripts.after = el('#ip-after').value;
        alert('Scriptler kaydedildi.');
        break;

      case 'save-settings':
        STATE.settings.maskSensitive = el('#ip-mask').checked;
        STATE.settings.captureBodies = el('#ip-bodies').checked;
        STATE.maxRecords = Math.max(50, Math.min(5000, Number(el('#ip-max').value) || 500));
        notify();
        break;

      case 'disable-tab':
        STATE.tabMode = false;
        STATE.channel?.close();
        STATE.channel = null;
        if (STATE.dashboard && !STATE.dashboard.closed) STATE.dashboard.close();
        STATE.dashboard = null;
        render();
        break;
    }
  } catch (err) {
    alert('İşlem hatası: ' + err.message);
  }
});

root.addEventListener('input', event => {
  if (event.target.id === 'ip-search') {
    STATE.filter = event.target.value;
    const cursor = event.target.selectionStart;
    render();
    const input = el('#ip-search');
    input?.focus();
    input?.setSelectionRange(cursor, cursor);
  }
});

D.addEventListener('fullscreenchange', () => {
  const btn = root.querySelector('[data-action="fullscreen"]');
  if (btn) btn.textContent = D.fullscreenElement === root
    ? 'Eski Boyuta Dön'
    : 'Tam Ekran';
});

/* =========================================
   API / PUBLIC CONTROL
========================================= */

const api = {
  show() {
    root.classList.remove('hidden');
  },
  hide() {
    root.classList.add('hidden');
  },
  openTab: openDashboard,
  enableTabMode() {
    if (!STATE.tabMode) {
      root.querySelector('[data-action="tabmode"]')?.click();
    }
  },
  disableTabMode() {
    if (STATE.tabMode) {
      root.querySelector('[data-action="tabmode"]')?.click();
    }
  },
  clear() {
    STATE.requests = [];
    STATE.selected = null;
    notify();
  },
  exportHAR,
  manualSend,
  destroy() {
    STATE.active = false;
    STATE.tabMode = false;
    STATE.channel?.close();
    if (STATE.dashboard && !STATE.dashboard.closed) STATE.dashboard.close();
    W.fetch = nativeFetch;
    NativeXHR.prototype.open = originalOpen;
    NativeXHR.prototype.send = originalSend;
    NativeXHR.prototype.setRequestHeader = originalSetHeader;
    root.remove();
    style.remove();
    delete W.__inspectorPro;
  },
  state: STATE
};

W.__inspectorPro = api;
render();

})();
