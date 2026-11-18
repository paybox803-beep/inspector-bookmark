
(() => {
'use strict';

/* INSPECTOR PRO - SINGLE FILE */

if (window.__inspectorPro) {
  window.__inspectorPro.show();
  return;
}

const W = window, D = document;
const CHANNEL = 'inspector-pro-live-v3';
const nativeFetch = W.fetch.bind(W);
const XHR = W.XMLHttpRequest;
const xhrOpen = XHR.prototype.open;
const xhrSend = XHR.prototype.send;
const xhrHeader = XHR.prototype.setRequestHeader;

const S = {
  active: true,
  tabMode: false,
  channel: null,
  dashboard: null,
  requests: [],
  selected: null,
  tab: 'traffic',
  filter: '',
  max: 500,
  mask: true,
  bodies: true,
  scripts: {before:'', after:''}
};

const sensitive = /authorization|cookie|token|secret|password|api[-_]?key/i;
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2,8);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({
  '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
})[c]);

const safe = v => {
  try { return typeof v === 'string' ? v : JSON.stringify(v,null,2) || ''; }
  catch { return String(v ?? ''); }
};
const limit = v => String(v ?? '').slice(0,150000);
const headersObject = h => {
  const out = {};
  try {
    const entries = h instanceof Headers ? [...h.entries()] : Object.entries(h || {});
    entries.forEach(([k,v]) => out[k] = S.mask && sensitive.test(k) ? '[REDACTED]' : String(v));
  } catch {}
  return out;
};
const parseHeaders = raw => {
  const out = {};
  String(raw || '').trim().split(/\r?\n/).forEach(line => {
    const i = line.indexOf(':');
    if (i > 0) out[line.slice(0,i).trim()] = line.slice(i+1).trim();
  });
  return out;
};
const selected = () => S.requests.find(r => r.id === S.selected) || null;

function publish(type='TRAFFIC_UPDATE') {
  if (!S.tabMode || !S.channel) return;
  try {
    S.channel.postMessage({
      source:'inspector-main',
      type,
      data:{
        requests:S.requests,
        selected:S.selected,
        active:S.active,
        tab:S.tab
      }
    });
  } catch {}
}

function notify() {
  render();
  publish();
}

function addRecord(r) {
  r.id ||= uid();
  r.time ||= Date.now();
  r.status ??= 'pending';
  r.requestHeaders ||= {};
  r.responseHeaders ||= {};
  r.requestBody ??= '';
  r.responseBody ??= '';
  S.requests.unshift(r);
  if (S.requests.length > S.max) S.requests.length = S.max;
  S.selected = r.id;
  notify();
  return r;
}

function updateRecord(id, changes) {
  const r = S.requests.find(x => x.id === id);
  if (!r) return;
  Object.assign(r,changes);
  notify();
}

function runHook(code, request, response) {
  if (!code.trim()) return {request,response};
  try {
    const fn = new Function('request','response',
      '"use strict";\n'+code+'\n;return {request,response};');
    return fn(request,response) || {request,response};
  } catch(e) {
    console.warn('Inspector Script Lab:',e);
    return {request,response};
  }
}

/* FETCH CAPTURE */
W.fetch = async function(input, init) {
  if (!S.active) return nativeFetch(input,init);

  let req;
  try { req = new Request(input,init); }
  catch { return nativeFetch(input,init); }

  const id = uid(), start = performance.now();
  let body = '';
  try {
    if (S.bodies && !['GET','HEAD'].includes(req.method)) {
      body = await req.clone().text();
    }
  } catch {}

  const original = {
    url:req.url,
    method:req.method,
    headers:headersObject(req.headers),
    body
  };

  addRecord({
    id,type:'fetch',method:req.method,url:req.url,
    requestHeaders:original.headers,
    requestBody:limit(body),
    status:'pending'
  });

  let outgoing = req;
  try {
    const hook = runHook(S.scripts.before,original,null);
    if (hook.request && hook.request !== original) {
      const x = hook.request;
      outgoing = new Request(x.url || req.url,{
        method:x.method || req.method,
        headers:x.headers || original.headers,
        body:['GET','HEAD'].includes(String(x.method || req.method).toUpperCase())
          ? undefined : (x.body ?? body),
        credentials:req.credentials,
        mode:req.mode,
        redirect:req.redirect
      });
    }

    const response = await nativeFetch(outgoing);
    let responseBody = '';
    try { if (S.bodies) responseBody = await response.clone().text(); } catch {}

    const responseData = {
      status:response.status,
      statusText:response.statusText,
      headers:headersObject(response.headers),
      body:limit(responseBody)
    };

    runHook(S.scripts.after,original,responseData);

    updateRecord(id,{
      status:response.status,
      statusText:response.statusText,
      responseHeaders:responseData.headers,
      responseBody:responseData.body,
      duration:Math.round(performance.now()-start)
    });
    return response;
  } catch(e) {
    updateRecord(id,{
      status:'error',error:String(e),
      duration:Math.round(performance.now()-start)
    });
    throw e;
  }
};

/* XHR CAPTURE */
const xhrData = new WeakMap();

XHR.prototype.open = function(method,url,...args) {
  xhrData.set(this,{
    method:String(method || 'GET').toUpperCase(),
    url:String(url),
    headers:{},
    id:uid()
  });
  return xhrOpen.call(this,method,url,...args);
};

XHR.prototype.setRequestHeader = function(k,v) {
  const m = xhrData.get(this);
  if (m) m.headers[k] = v;
  return xhrHeader.call(this,k,v);
};

XHR.prototype.send = function(body) {
  const m = xhrData.get(this);
  if (!m || !S.active) return xhrSend.call(this,body);

  const start = performance.now();
  addRecord({
    id:m.id,type:'xhr',method:m.method,url:m.url,
    requestHeaders:headersObject(m.headers),
    requestBody:S.bodies ? limit(safe(body)) : '',
    status:'pending'
  });

  this.addEventListener('loadend',() => {
    let responseBody = '';
    try {
      if (S.bodies) {
        responseBody = typeof this.responseText === 'string'
          ? this.responseText : safe(this.response);
      }
    } catch {}
    let responseHeaders = {};
    try { responseHeaders = headersObject(parseHeaders(this.getAllResponseHeaders())); } catch {}

    updateRecord(m.id,{
      status:this.status || 'error',
      statusText:this.statusText,
      responseHeaders,
      responseBody:limit(responseBody),
      duration:Math.round(performance.now()-start)
    });
  },{once:true});

  return xhrSend.call(this,body);
};

/* MANUAL REQUEST */
async function manualSend(o={}) {
  const method = String(o.method || 'GET').toUpperCase();
  const url = String(o.url || '').trim();
  if (!url) throw Error('URL gerekli.');

  const headers = {};
  String(o.headers || '').split(/\r?\n/).forEach(line => {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0,i).trim()] = line.slice(i+1).trim();
  });

  const id = uid(), start = performance.now();
  addRecord({
    id,type:'manual',method,url,
    requestHeaders:headersObject(headers),
    requestBody:limit(o.body || ''),
    status:'sending'
  });

  try {
    const response = await nativeFetch(url,{
      method,headers,
      body:['GET','HEAD'].includes(method) ? undefined : o.body,
      credentials:'same-origin'
    });
    let text = '';
    try { if (S.bodies) text = await response.clone().text(); } catch {}
    updateRecord(id,{
      status:response.status,
      statusText:response.statusText,
      responseHeaders:headersObject(response.headers),
      responseBody:limit(text),
      duration:Math.round(performance.now()-start)
    });
    return response;
  } catch(e) {
    updateRecord(id,{status:'error',error:String(e)});
    throw e;
  }
}

/* EXPORT AND COPY */
function download(name,content,type='application/json') {
  const blob = new Blob([content],{type});
  const url = URL.createObjectURL(blob);
  const a = D.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url),1500);
}

function exportHAR() {
  const entries = S.requests.map(r => ({
    startedDateTime:new Date(r.time).toISOString(),
    time:r.duration || 0,
    request:{
      method:r.method,url:r.url,httpVersion:'HTTP/1.1',
      headers:Object.entries(r.requestHeaders || {}).map(([name,value])=>({name,value})),
      queryString:[],headersSize:-1,
      bodySize:(r.requestBody || '').length,
      postData:r.requestBody ? {mimeType:'text/plain',text:r.requestBody} : undefined
    },
    response:{
      status:Number(r.status) || 0,
      statusText:r.statusText || '',
      httpVersion:'HTTP/1.1',
      headers:Object.entries(r.responseHeaders || {}).map(([name,value])=>({name,value})),
      content:{size:(r.responseBody || '').length,mimeType:'text/plain',text:r.responseBody || ''},
      headersSize:-1,bodySize:(r.responseBody || '').length
    },
    cache:{},timings:{send:0,wait:r.duration || 0,receive:0}
  }));

  download('inspector-pro.har',JSON.stringify({
    log:{version:'1.2',creator:{name:'Inspector Pro',version:'3.0'},entries}
  },null,2));
}

function curl(r) {
  const q = v => "'" + String(v ?? '').replace(/'/g,"'\\''") + "'";
  let out = 'curl -X '+q(r.method || 'GET')+' '+q(r.url);
  Object.entries(r.requestHeaders || {}).forEach(([k,v]) => {
    out += ' -H '+q(k+': '+v);
  });
  if (r.requestBody) out += ' --data-raw '+q(r.requestBody);
  return out;
}

function copy(value) {
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(value).catch(() => fallbackCopy(value));
  } else fallbackCopy(value);
}
function fallbackCopy(value) {
  const t = D.createElement('textarea');
  t.value = value;
  D.body.appendChild(t);
  t.select();
  try { D.execCommand('copy'); } catch {}
  t.remove();
}
  
/* COMPACT USER INTERFACE */
const style = D.createElement('style');
style.textContent = `
#mini-burp {
  position:fixed;
  z-index:2147483646;
  right:12px;
  bottom:68px;
  width:min(390px,calc(100vw - 20px));
  height:min(510px,calc(100dvh - 90px));
  display:flex;
  flex-direction:column;
  overflow:hidden;
  color:#e8eef8;
  background:#111722;
  border:1px solid #354258;
  border-radius:14px;
  box-shadow:0 12px 45px #0009;
  font:12px/1.45 system-ui,Arial,sans-serif;
}
#mini-burp * {box-sizing:border-box}
#mini-burp.hidden {display:none!important}
#mini-burp button,
#mini-burp input,
#mini-burp textarea,
#mini-burp select {font:inherit}
#mini-burp button {
  color:#e8eef8;
  background:#293951;
  border:1px solid #40516b;
  border-radius:7px;
  padding:6px 9px;
  cursor:pointer;
}
#mini-burp button:hover {background:#3a4d69}
#mini-burp button.active {background:#176b55}
#mini-burp .top {
  display:flex;
  align-items:center;
  gap:6px;
  padding:8px;
  background:#1b2637;
}
#mini-burp .brand {
  font-weight:800;
  margin-right:auto;
  white-space:nowrap;
}
#mini-burp .top button {padding:5px 7px}
#mini-burp .tabs {
  display:flex;
  gap:5px;
  padding:7px;
  border-bottom:1px solid #344157;
}
#mini-burp .tabs button {flex:1}
#mini-burp #ip-content {
  display:flex;
  flex:1;
  min-height:0;
  flex-direction:column;
  overflow:hidden;
}
#mini-burp .layout {
  display:grid;
  grid-template-columns: minmax(115px,38%) 1fr;
  flex:1;
  min-height:0;
}
#mini-burp .list {
  overflow:auto;
  border-right:1px solid #344157;
}
#mini-burp .details {
  overflow:auto;
  padding:9px;
  min-width:0;
}
#mini-burp .item {
  padding:8px;
  border-bottom:1px solid #273448;
  cursor:pointer;
  overflow-wrap:anywhere;
}
#mini-burp .item.selected {background:#263750}
#mini-burp .muted {color:#9eacc1}
#mini-burp .field {margin:7px 0;padding:0 8px}
#mini-burp label {
  display:block;
  color:#aebbd0;
  margin:7px 0 4px;
}
#mini-burp input:not([type=checkbox]),
#mini-burp textarea,
#mini-burp select {
  width:100%;
  min-width:0;
  padding:8px;
  color:#edf2fa;
  background:#0b111b;
  border:1px solid #39475e;
  border-radius:7px;
}
#mini-burp input[type=checkbox] {
  width:auto;
  margin-right:6px;
}
#mini-burp textarea {
  min-height:65px;
  resize:vertical;
}
#mini-burp pre {
  max-height:130px;
  overflow:auto;
  white-space:pre-wrap;
  overflow-wrap:anywhere;
  background:#0b111b;
  padding:8px;
  border-radius:7px;
  margin:5px 0 10px;
}
#mini-burp h3 {font-size:14px;margin:4px 0 8px}
#mini-burp h4 {font-size:12px;margin:9px 0 4px}
#mini-burp .toolbar {
  display:flex;
  flex-wrap:wrap;
  gap:5px;
  margin:7px 0;
}
#mini-burp .bottom {
  padding:6px 9px;
  color:#aab7c9;
  background:#1b2637;
}
#mini-burp:fullscreen {
  width:100vw;
  height:100vh;
  max-width:none;
  max-height:none;
  inset:0;
  border:0;
  border-radius:0;
}
#ip-launcher {
  position:fixed;
  z-index:2147483647;
  right:15px;
  bottom:15px;
  width:46px;
  height:46px;
  border:1px solid #638276;
  border-radius:50%;
  background:#176b55;
  color:white;
  font:bold 13px system-ui;
  box-shadow:0 5px 20px #0009;
  cursor:pointer;
}
#ip-launcher.hidden {display:none!important}
@media(max-width:600px) {
  #mini-burp {
    width:calc(100vw - 12px);
    height:min(72dvh,560px);
    right:6px;
    bottom:68px;
  }
  #mini-burp .top {gap:4px;padding:6px}
  #mini-burp .top button {font-size:10px;padding:5px}
  #mini-burp .layout {grid-template-columns:1fr}
  #mini-burp .list {
    max-height:34%;
    border-right:0;
    border-bottom:1px solid #344157;
  }
}
`;
D.head.appendChild(style);

/* PANEL */
const root = D.createElement('section');
root.id = 'mini-burp';
root.innerHTML = `
 <div class="top">
  <span class="brand">Inspector Pro</span>
  <button data-action="pause">Pause</button>
  <button data-action="tabmode">Sekme</button>
  <button data-action="opentab">Dashboard</button>
  <button data-action="fullscreen">⛶</button>
  <button data-action="hide">×</button>
 </div>
 <div class="tabs">
  <button data-tab="traffic">Traffic</button>
  <button data-tab="repeater">Repeater</button>
  <button data-tab="scripts">Script Lab</button>
  <button data-tab="settings">Ayarlar</button>
 </div>
 <div id="ip-content"></div>
 <div class="bottom" id="ip-status">Hazır · Fetch + XHR</div>
`;
D.body.appendChild(root);

/* FLOATING BUTTON */
const launcher = D.createElement('button');
launcher.id = 'ip-launcher';
launcher.textContent = 'IP';
launcher.title = 'Inspector Pro aç';
D.body.appendChild(launcher);
root.classList.add('hidden');

launcher.addEventListener('click',() => {
  root.classList.remove('hidden');
  launcher.classList.add('hidden');
});

function el(q) { return root.querySelector(q); }
function btn(label,action) {
  return `<button data-action="${action}">${label}</button>`;
}

/* TRAFFIC TAB */
function renderTraffic() {
  const q = S.filter.toLowerCase();
  const list = S.requests.filter(r =>
    [r.url,r.method,r.status,r.type].join(' ').toLowerCase().includes(q)
  );
  const r = selected();

  return `
  <div class="field">
   <input id="ip-search" placeholder="İsteklerde ara..." value="${esc(S.filter)}">
   <div class="toolbar">
    ${btn('HAR indir','har')}
    ${btn('cURL kopyala','curl')}
    ${btn('Ham istek','rawrequest')}
    ${btn('Temizle','clear')}
   </div>
  </div>
  <div class="layout">
   <div class="list">
    ${list.map(x => `
     <div class="item ${x.id===S.selected?'selected':''}" data-id="${esc(x.id)}">
      <b>${esc(x.method)}</b>
      <span class="muted">${esc(x.status)}</span>
      <div>${esc(x.url)}</div>
      <small class="muted">${esc(x.type)} · ${x.duration || 0} ms</small>
     </div>
    `).join('')}
   </div>
   <div class="details">
    ${r ? renderRecord(r) : '<p class="muted">Henüz istek yok. Sayfada gezinerek trafik oluştur.</p>'}
   </div>
  </div>`;
}

function renderRecord(r) {
  return `
   <h3>${esc(r.method)} · ${esc(r.status)}</h3>
   <div class="muted">${esc(r.url)}</div>
   <div class="toolbar">
    ${btn('cURL','curl')}
    ${btn('Ham istek','rawrequest')}
    ${btn('Ham yanıt','rawresponse')}
    ${btn('Repeater’a aktar','to-repeater')}
   </div>
   <h4>Request Headers</h4>
   <pre>${esc(safe(r.requestHeaders))}</pre>
   <h4>Request Body</h4>
   <pre>${esc(r.requestBody)}</pre>
   <h4>Response Headers</h4>
   <pre>${esc(safe(r.responseHeaders))}</pre>
   <h4>Response Body</h4>
   <pre>${esc(r.responseBody)}</pre>
   ${r.error ? `<pre>${esc(r.error)}</pre>` : ''}
  `;
}

/* REPEATER TAB */
function renderRepeater() {
  const r = selected() || {};
  return `
   <div class="details">
    <h3>Repeater / Manuel İstek</h3>
    <label>Method</label>
    <select id="rp-method">
     ${['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'].map(m =>
       `<option ${r.method===m?'selected':''}>${m}</option>`).join('')}
    </select>
    <label>URL</label>
    <input id="rp-url" value="${esc(r.url || '')}" placeholder="https://example.com/api">
    <label>Headers</label>
    <textarea id="rp-headers" placeholder="Content-Type: application/json">${esc(
      Object.entries(r.requestHeaders || {}).map(([k,v])=>k+': '+v).join('\n')
    )}</textarea>
    <label>Body</label>
    <textarea id="rp-body">${esc(r.requestBody || '')}</textarea>
    <div class="toolbar">
     ${btn('İsteği gönder','send')}
     ${btn('Seçili isteği yükle','load-selected')}
    </div>
    <p class="muted">İstekler tarayıcının aynı kaynak ve CORS kurallarına tabidir.</p>
   </div>`;
}

/* SCRIPT LAB */
function renderScripts() {
  return `
   <div class="details">
    <h3>Script Lab</h3>
    <p class="muted">Yalnızca yetkili olduğun test sistemlerinde kullan.</p>
    <label>Before Request</label>
    <textarea id="ip-before" style="min-height:105px">${esc(S.scripts.before)}</textarea>
    <label>After Response</label>
    <textarea id="ip-after" style="min-height:105px">${esc(S.scripts.after)}</textarea>
    <div class="toolbar">${btn('Scriptleri kaydet','save-scripts')}</div>
   </div>`;
}

/* SETTINGS */
function renderSettings() {
  return `
   <div class="details">
    <h3>Ayarlar</h3>
    <label><input type="checkbox" id="ip-mask" ${S.mask?'checked':''}> Hassas header maskele</label>
    <label><input type="checkbox" id="ip-bodies" ${S.bodies?'checked':''}> Request / Response body yakala</label>
    <label>Maksimum kayıt</label>
    <input id="ip-max" type="number" min="50" max="5000" value="${S.max}">
    <div class="toolbar">
     ${btn('Ayarları kaydet','save-settings')}
     ${btn('Sekme modunu kapat','disable-tab')}
    </div>
    <p class="muted">Gizli bilgiler dışa aktarım ve kopyalama işlemlerinde maskelenir.</p>
   </div>`;
}

/* RENDER */
function render() {
  if (!root.isConnected) return;
  const content = el('#ip-content');
  if (S.tab==='traffic') content.innerHTML = renderTraffic();
  else if (S.tab==='repeater') content.innerHTML = renderRepeater();
  else if (S.tab==='scripts') content.innerHTML = renderScripts();
  else content.innerHTML = renderSettings();

  el('#ip-status').textContent =
    `${S.requests.length} kayıt · ${S.tabMode?'Canlı dashboard açık':'Sekme modu kapalı'}`;

  root.querySelectorAll('[data-tab]').forEach(b =>
    b.classList.toggle('active',b.dataset.tab===S.tab)
  );

  const pause = root.querySelector('[data-action="pause"]');
  if (pause) pause.textContent = S.active ? 'Pause' : 'Resume';
  const tab = root.querySelector('[data-action="tabmode"]');
  if (tab) tab.classList.toggle('active',S.tabMode);
  }
  
/* LIVE DASHBOARD */
function openDashboard() {
  if (!S.tabMode || !S.channel) {
    alert('Önce Sekme modunu etkinleştir.');
    return;
  }

  if (S.dashboard && !S.dashboard.closed) {
    S.dashboard.focus();
    return;
  }

  const tab = W.open('', 'InspectorProDashboard');
  if (!tab) {
    alert('Yeni sekme açılamadı. Popup iznini kontrol et.');
    return;
  }

  S.dashboard = tab;

  tab.document.write(`<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Inspector Pro Dashboard</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#101722;color:#e8eef8;font:13px system-ui}
header{position:sticky;top:0;background:#1d293b;padding:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
button{background:#293951;color:white;border:1px solid #40516b;padding:8px;border-radius:7px;cursor:pointer}
button.active{background:#176b55}
main{padding:12px}
nav{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
input,textarea,select{width:100%;background:#0a111c;color:white;border:1px solid #40516b;padding:9px;border-radius:7px;margin:4px 0}
textarea{min-height:70px}
.layout{display:grid;grid-template-columns:minmax(180px,32%) 1fr;gap:10px}
.list{overflow:auto;max-height:75vh}
.item{padding:9px;border-bottom:1px solid #30405a;cursor:pointer;overflow-wrap:anywhere}
.item.selected{background:#263750}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a111c;padding:10px;border-radius:7px;max-height:300px;overflow:auto}
.muted{color:#a6b5c9}
@media(max-width:650px){.layout{grid-template-columns:1fr}.list{max-height:30vh}}
</style>
</head>
<body>
<header>
 <b>Inspector Pro · Live</b>
 <span id="connection">Bağlanıyor...</span>
 <button id="fullscreen">Tam ekran</button>
</header>
<main id="app">Veri bekleniyor...</main>
<script>
const ch = new BroadcastChannel('${CHANNEL}');
const app = document.getElementById('app');
const connection = document.getElementById('connection');
let data = {requests:[]};
let selected = null;
let page = 'traffic';
const esc = v => String(v ?? '').replace(/[&<>"']/g,c=>({
 '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
})[c]);

function render() {
 const requests = data.requests || [];
 const current = requests.find(r=>r.id===selected) || requests.find(r=>r.id===data.selected) || requests[0];
 if (!selected && current) selected=current.id;

 app.innerHTML = \`
 <nav>
  <button data-tab="traffic" class="\${page==='traffic'?'active':''}">Traffic</button>
  <button data-tab="repeater" class="\${page==='repeater'?'active':''}">Repeater</button>
  <button data-tab="settings" class="\${page==='settings'?'active':''}">Durum</button>
 </nav>
 \${page==='traffic' ? \`
  <input id="search" placeholder="Trafikte ara...">
  <div class="layout">
   <div class="list">
    \${requests.map(r=>\`
     <div class="item \${r.id===selected?'selected':''}" data-id="\${esc(r.id)}">
      <b>\${esc(r.method)}</b> \${esc(r.status)}
      <div>\${esc(r.url)}</div>
      <small class="muted">\${esc(r.type)} · \${r.duration||0} ms</small>
     </div>
    \`).join('')}
   </div>
   <div>
    \${current ? \`
     <h3>\${esc(current.method)} · \${esc(current.status)}</h3>
     <p>\${esc(current.url)}</p>
     <button id="to-repeater">Repeater’a aktar</button>
     <h4>Request Headers</h4><pre>\${esc(JSON.stringify(current.requestHeaders,null,2))}</pre>
     <h4>Request Body</h4><pre>\${esc(current.requestBody)}</pre>
     <h4>Response Headers</h4><pre>\${esc(JSON.stringify(current.responseHeaders,null,2))}</pre>
     <h4>Response Body</h4><pre>\${esc(current.responseBody)}</pre>
    \`:'Henüz istek yok.'}
   </div>
  </div>
 \` : page==='repeater' ? \`
  <h3>Manuel istek</h3>
  <select id="method">
   <option>GET</option><option>POST</option><option>PUT</option>
   <option>PATCH</option><option>DELETE</option><option>HEAD</option>
  </select>
  <input id="url" placeholder="URL" value="\${esc(current?.url||'')}">
  <textarea id="headers" placeholder="Header: value"></textarea>
  <textarea id="body" placeholder="Request body"></textarea>
  <button id="send">Gönder</button>
 \` : \`
  <h3>Bağlantı durumu</h3>
  <p>Canlı aktarım: Açık</p>
  <p>Toplam kayıt: \${requests.length}</p>
  <p>Yakalama: \${data.active?'Aktif':'Duraklatıldı'}</p>
 \`}
 \`;

 app.querySelectorAll('[data-tab]').forEach(b=>{
  b.onclick=()=>{page=b.dataset.tab;render()};
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
 if(transfer) transfer.onclick=()=>{page='repeater';render()};

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
 if(!msg || msg.source!=='inspector-main') return;
 connection.textContent='● Canlı bağlantı';
 if(msg.type==='SNAPSHOT'||msg.type==='TRAFFIC_UPDATE'){
  data=msg.data || {requests:[]};
  render();
 }
};

ch.postMessage({source:'inspector-dashboard',type:'REQUEST_SNAPSHOT'});
document.getElementById('fullscreen').onclick=async()=>{
 try {
  if(document.fullscreenElement) await document.exitFullscreen();
  else await document.documentElement.requestFullscreen();
 } catch {}
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

/* EVENT HANDLERS */
root.addEventListener('click',async event=>{
  const target = event.target;
  if (!(target instanceof Element)) return;

  const tab = target.closest('[data-tab]')?.dataset.tab;
  const item = target.closest('[data-id]');
  const action = target.closest('[data-action]')?.dataset.action;

  if (tab) {
    S.tab=tab;
    render();
    return;
  }

  if (item) {
    S.selected=item.dataset.id;
    render();
    publish();
    return;
  }

  if (!action) return;

  try {
    switch(action) {
      case 'pause':
        S.active=!S.active;
        notify();
        break;

      case 'tabmode':
        if (!S.tabMode) {
          if (!('BroadcastChannel' in W)) {
            alert('Bu tarayıcı BroadcastChannel desteklemiyor.');
            break;
          }
          S.channel=new BroadcastChannel(CHANNEL);
          S.tabMode=true;

          S.channel.onmessage=async e=>{
            const msg=e.data;
            if (!msg || msg.source!=='inspector-dashboard') return;

            if (msg.type==='REQUEST_SNAPSHOT') publish('SNAPSHOT');

            if (msg.type==='MANUAL_SEND') {
              try { await manualSend(msg.data); }
              catch(err) { console.error('Inspector request:',err); }
            }

            if (msg.type==='DASHBOARD_CLOSED') S.dashboard=null;
          };

          publish('SNAPSHOT');
        } else {
          S.tabMode=false;
          S.channel?.close();
          S.channel=null;
          if (S.dashboard && !S.dashboard.closed) S.dashboard.close();
          S.dashboard=null;
        }
        render();
        break;

      case 'opentab':
        openDashboard();
        break;

      case 'fullscreen':
        if (D.fullscreenElement===root) await D.exitFullscreen();
        else await root.requestFullscreen();
        break;

      case 'hide':
        if (D.fullscreenElement===root) await D.exitFullscreen();
        root.classList.add('hidden');
        launcher.classList.remove('hidden');
        break;

      case 'har':
        exportHAR();
        break;

      case 'clear':
        S.requests=[];
        S.selected=null;
        notify();
        break;

      case 'curl': {
        const r=selected();
        if (r) copy(curl(r));
        break;
      }

      case 'rawrequest': {
        const r=selected();
        if (r) copy(
          r.method+' '+r.url+'\n'+
          Object.entries(r.requestHeaders || {}).map(([k,v])=>k+': '+v).join('\n')+
          '\n\n'+(r.requestBody || '')
        );
        break;
      }

      case 'rawresponse': {
        const r=selected();
        if (r) copy(
          'HTTP '+r.status+' '+(r.statusText || '')+'\n'+
          Object.entries(r.responseHeaders || {}).map(([k,v])=>k+': '+v).join('\n')+
          '\n\n'+(r.responseBody || '')
        );
        break;
      }

      case 'to-repeater':
      case 'load-selected':
        S.tab='repeater';
        render();
        break;

      case 'send':
        await manualSend({
          method:el('#rp-method').value,
          url:el('#rp-url').value,
          headers:el('#rp-headers').value,
          body:el('#rp-body').value
        });
        break;

      case 'save-scripts':
        S.scripts.before=el('#ip-before').value;
        S.scripts.after=el('#ip-after').value;
        alert('Scriptler kaydedildi.');
        break;

      case 'save-settings':
        S.mask=el('#ip-mask').checked;
        S.bodies=el('#ip-bodies').checked;
        S.max=Math.max(50,Math.min(5000,Number(el('#ip-max').value)||500));
        S.requests.length=Math.min(S.requests.length,S.max);
        notify();
        break;

      case 'disable-tab':
        S.tabMode=false;
        S.channel?.close();
        S.channel=null;
        if (S.dashboard && !S.dashboard.closed) S.dashboard.close();
        S.dashboard=null;
        render();
        break;
    }
  } catch(err) {
    alert('Inspector Pro: '+err.message);
    console.error(err);
  }
});

/* SEARCH WITHOUT FULL RENDER */
root.addEventListener('input',event=>{
  if (event.target.id==='ip-search') {
    S.filter=event.target.value;
    const q=S.filter.toLowerCase();
    root.querySelectorAll('.item[data-id]').forEach(item=>{
      item.style.display=item.textContent.toLowerCase().includes(q)?'':'none';
    });
  }
});

D.addEventListener('fullscreenchange',()=>{
  const b=root.querySelector('[data-action="fullscreen"]');
  if (b) b.textContent=D.fullscreenElement===root?'↙':'⛶';
});

/* PUBLIC API */
const api = {
  show() {
    root.classList.remove('hidden');
    launcher.classList.add('hidden');
  },
  hide() {
    root.classList.add('hidden');
    launcher.classList.remove('hidden');
  },
  openTab:openDashboard,
  enableTabMode() {
    if (!S.tabMode) root.querySelector('[data-action="tabmode"]')?.click();
  },
  disableTabMode() {
    if (S.tabMode) root.querySelector('[data-action="tabmode"]')?.click();
  },
  clear() {
    S.requests=[];
    S.selected=null;
    notify();
  },
  exportHAR,
  manualSend,
  destroy() {
    S.active=false;
    S.tabMode=false;
    S.channel?.close();
    if (S.dashboard && !S.dashboard.closed) S.dashboard.close();
    W.fetch=nativeFetch;
    XHR.prototype.open=xhrOpen;
    XHR.prototype.send=xhrSend;
    XHR.prototype.setRequestHeader=xhrHeader;
    root.remove();
    launcher.remove();
    style.remove();
    delete W.__inspectorPro;
  },
  state:S
};

W.__inspectorPro=api;
render();

})();
          
