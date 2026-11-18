
(() => {
'use strict';

if (window.__miniBurp?.destroy) {
  window.__miniBurp.show();
  return;
}

const W = window;
const D = document;
const X = XMLHttpRequest.prototype;
const originalFetch = W.fetch.bind(W);
const originalOpen = X.open;
const originalSend = X.send;
const originalHeader = X.setRequestHeader;
const originalAbort = X.abort;
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;

const state = {
  enabled: true,
  requests: [],
  queue: [],
  selected: null,
  id: 0,
  before: '',
  after: '',
  max: 1500
};

const escapeHTML = s => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
}[c]));

const clone = x => JSON.parse(JSON.stringify(x ?? null));

function headersObject(h) {
  const out = {};
  if (h instanceof Headers) h.forEach((v,k) => out[k] = v);
  else if (Array.isArray(h)) h.forEach(([k,v]) => out[k] = v);
  else if (h && typeof h === 'object') Object.assign(out,h);
  return out;
}

function requestText(r) {
  const u = new URL(r.url, location.href);
  const path = u.pathname + u.search;
  return [
    `${r.method} ${path} HTTP/1.1`,
    `Host: ${u.host}`,
    ...Object.entries(r.headers || {}).map(([k,v]) => `${k}: ${v}`),
    '',
    r.body || ''
  ].join('\r\n');
}

function shellQuote(s) {
  return "'" + String(s ?? '').replace(/'/g, "'\\''") + "'";
}

function toCurl(r) {
  let out = `curl -i -X ${shellQuote(r.method)} ${shellQuote(r.url)}`;
  for (const [k,v] of Object.entries(r.headers || {})) {
    out += ` \\\n  -H ${shellQuote(k + ': ' + v)}`;
  }
  if (r.body && !['GET','HEAD'].includes(r.method)) {
    out += ` \\\n  --data-raw ${shellQuote(r.body)}`;
  }
  return out;
}

function toFetch(r) {
  return `fetch(${JSON.stringify(r.url)}, {\n` +
    `  method: ${JSON.stringify(r.method)},\n` +
    `  headers: ${JSON.stringify(r.headers || {},null,2)},\n` +
    (r.body ? `  body: ${JSON.stringify(r.body)},\n` : '') +
    `  credentials: "same-origin"\n});`;
}

function saveFile(name, content, type='application/json') {
  const blob = new Blob([content], {type});
  const url = URL.createObjectURL(blob);
  const a = D.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 3000);
}

function harExport() {
  const entries = [...state.requests].reverse().filter(r => r.done).map(r => {
    const started = new Date(r.created);
    const reqHeaders = Object.entries(r.headers || {}).map(([name,value]) => ({name,value:String(value)}));
    const resHeaders = Object.entries(r.responseHeaders || {}).map(([name,value]) => ({name,value:String(value)}));
    return {
      startedDateTime: started.toISOString(),
      time: r.duration || 0,
      request: {
        method: r.method,
        url: r.url,
        httpVersion: 'HTTP/1.1',
        headers: reqHeaders,
        queryString: [...new URL(r.url, location.href).searchParams.entries()].map(([name,value]) => ({name,value})),
        headersSize: -1,
        bodySize: r.body ? new Blob([r.body]).size : 0,
        postData: r.body ? {mimeType:r.headers?.['Content-Type'] || '', text:r.body} : undefined
      },
      response: {
        status: r.status || 0,
        statusText: '',
        httpVersion: 'HTTP/1.1',
        headers: resHeaders,
        cookies: [],
        content: {size: new Blob([r.responseBody || '']).size, mimeType:r.responseHeaders?.['content-type'] || '', text:r.responseBody || ''},
        redirectURL: '',
        headersSize: -1,
        bodySize: -1
      },
      cache: {},
      timings: {send:0,wait:r.duration || 0,receive:0},
      _type: r.type,
      _error: r.error || ''
    };
  });

  saveFile('inspector-traffic.har', JSON.stringify({
    log: {
      version:'1.2',
      creator:{name:'Inspector Pro',version:'2.0'},
      entries
    }
  },null,2));
}

function add(r) {
  r.id = ++state.id;
  r.created = new Date().toISOString();
  r.done = false;
  r.headers = headersObject(r.headers);
  state.requests.unshift(r);
  state.selected = r;
  if (state.requests.length > state.max) state.requests.length = state.max;

  if (state.enabled) state.queue.push(r);
  else dispatch(r);

  notify();
  return r;
}

function notify() {
  try {
    if (dashboard && !dashboard.closed) renderDashboard();
  } catch {}
  try { renderOverlay(); } catch {}
}

let dashboard = null;

async function runScript(source, request, response) {
  if (!source.trim()) return {request,response};
  const fn = new AsyncFunction('request','response','return (async()=>{\n' + source + '\n})()');
  const result = await fn(clone(request), clone(response));
  return result || {request,response};
}

async function dispatch(r) {
  if (!r || r.done || r.dropped || r.started) return;

  r.started = Date.now();
  state.queue = state.queue.filter(x => x !== r);
  notify();

  try {
    let edited = {
      url:r.url,
      method:r.method,
      headers:headersObject(r.headers),
      body:r.body
    };

    const before = await runScript(state.before, edited, null);
    if (before.request) edited = before.request;

    const result = await r.send(edited);
    let finalResult = result;

    const after = await runScript(state.after, edited, result);
    if (after.response) finalResult = after.response;

    r.url = edited.url;
    r.method = edited.method;
    r.headers = edited.headers;
    r.body = edited.body;
    r.status = finalResult.status;
    r.responseHeaders = finalResult.headers || {};
    r.responseBody = finalResult.body ?? '';
    r.done = true;
    r.duration = Date.now() - r.started;
  } catch(e) {
    r.error = String(e?.message || e);
    r.done = true;
    r.duration = Date.now() - r.started;
  }

  notify();
}

function forwardAll() {
  const pending = [...state.queue];
  pending.forEach(dispatch);
}

function replay(r) {
  if (!r) return;
  const copy = {
    type:'replay',
    url:r.url,
    method:r.method,
    headers:headersObject(r.headers),
    body:r.body || '',
    send: manualSend
  };
  add(copy);
}

async function manualSend(req) {
  const method = String(req.method || 'GET').toUpperCase();
  const opts = {
    method,
    headers:headersObject(req.headers),
    credentials:'same-origin'
  };
  if (!['GET','HEAD'].includes(method) && req.body !== '') opts.body = req.body;

  const response = await originalFetch(req.url, opts);
  const body = await response.clone().text().catch(() => '[Response body unavailable]');
  return {
    status:response.status,
    headers:Object.fromEntries(response.headers.entries()),
    body
  };
}

/* FETCH INTERCEPT */
W.fetch = function(input, init={}) {
  const req = input instanceof Request ? input : null;
  const url = req ? req.url : String(input);
  const method = String(init.method || req?.method || 'GET').toUpperCase();
  const headers = headersObject(init.headers || req?.headers);
  const bodyPromise = init.body !== undefined
    ? Promise.resolve(init.body)
    : req ? req.clone().text() : Promise.resolve('');

  return bodyPromise.then(body => new Promise((resolve,reject) => {
    let settled = false;

    const r = {
      type:'fetch',
      url,method,headers,body:body == null ? '' : String(body),
      cancel:() => {
        if (!settled) {
          settled = true;
          reject(new DOMException('Request dropped by Inspector','AbortError'));
        }
      },
      send:async edited => {
        const opts = {
          method:edited.method,
          headers:edited.headers,
          credentials:req?.credentials || 'same-origin',
          mode:req?.mode,
          cache:req?.cache,
          redirect:req?.redirect,
          referrer:req?.referrer,
          integrity:req?.integrity,
          signal:init.signal || req?.signal
        };
        if (!['GET','HEAD'].includes(edited.method) && edited.body !== '') opts.body = edited.body;

        const response = await originalFetch(edited.url,opts);
        const text = await response.clone().text().catch(() => '[Response unavailable]');
        if (!settled) {
          settled = true;
          resolve(response);
        }
        return {
          status:response.status,
          headers:Object.fromEntries(response.headers.entries()),
          body:text
        };
      }
    };
    add(r);
  }));
};

/* XHR INTERCEPT */
const xhrMeta = new WeakMap();

X.open = function(method,url,...args) {
  xhrMeta.set(this,{
    method:String(method).toUpperCase(),
    url:String(url),
    args,
    headers:{}
  });
  return this;
};

X.setRequestHeader = function(k,v) {
  const meta = xhrMeta.get(this);
  if (meta) {
    meta.headers[k] = meta.headers[k] ? meta.headers[k] + ', ' + v : String(v);
    return;
  }
  return originalHeader.call(this,k,v);
};

X.send = function(body) {
  const xhr = this;
  const meta = xhrMeta.get(xhr) || {method:'GET',url:'',args:[],headers:{}};

  const r = {
    type:'xhr',
    url:meta.url,
    method:meta.method,
    headers:headersObject(meta.headers),
    body:body == null ? '' : String(body),
    cancel:() => {
      try { originalAbort.call(xhr); } catch {}
    },
    send:edited => new Promise((resolve,reject) => {
      let completed = false;
      try {
        originalOpen.call(xhr,edited.method,edited.url,...meta.args);
        Object.entries(edited.headers || {}).forEach(([k,v]) => {
          originalHeader.call(xhr,k,String(v));
        });

        xhr.addEventListener('loadend',() => {
          if (completed) return;
          completed = true;
          let responseBody = '';
          try {
            responseBody = xhr.responseType === '' || xhr.responseType === 'text'
              ? xhr.responseText
              : '[Response type: ' + xhr.responseType + ']';
          } catch {}
          const responseHeaders = {};
          try {
            xhr.getAllResponseHeaders().trim().split(/[\r\n]+/).forEach(line => {
              const i = line.indexOf(':');
              if (i > 0) responseHeaders[line.slice(0,i).trim()] = line.slice(i+1).trim();
            });
          } catch {}
          resolve({status:xhr.status,headers:responseHeaders,body:responseBody});
        },{once:true});

        xhr.addEventListener('error',() => {
          if (!completed) {completed=true;reject(Error('XHR network error'));}
        },{once:true});

        xhr.addEventListener('abort',() => {
          if (!completed) {completed=true;reject(Error('XHR aborted'));}
        },{once:true});

        originalSend.call(xhr,edited.body === '' ? null : edited.body);
      } catch(e) { reject(e); }
    })
  };

  add(r);
};

/* OVERLAY */
const style = D.createElement('style');
style.textContent = `
#mb-icon{position:fixed;right:15px;bottom:15px;width:50px;height:50px;border-radius:50%;background:#2563eb;color:white;z-index:2147483647;border:0;font-weight:bold;cursor:pointer}
#mb-panel{position:fixed;z-index:2147483646;right:10px;bottom:75px;width:min(520px,96vw);height:min(400px,70vh);background:#0b1220;color:white;border:1px solid #475569;border-radius:12px;display:none;flex-direction:column;overflow:hidden;font:12px monospace;box-shadow:0 10px 40px #000}
#mb-panel.open{display:flex}
#mb-panel button{background:#263449;color:white;border:1px solid #475569;padding:7px;border-radius:5px;cursor:pointer}
#mb-head{background:#172338;padding:10px;display:flex;justify-content:space-between}
#mb-list{overflow:auto;flex:1}
#mb-list button{display:block;width:100%;text-align:left;border:0;border-bottom:1px solid #334155;overflow-wrap:anywhere}
#mb-foot{display:flex;gap:5px;padding:8px;flex-wrap:wrap}
`;
D.head.appendChild(style);

const icon = D.createElement('button');
icon.id = 'mb-icon';
icon.textContent = 'MB';

const panel = D.createElement('div');
panel.id = 'mb-panel';
panel.innerHTML = `
<header id="mb-head"><b>INSPECTOR PRO</b>
<span><button id="mb-open">OPEN TAB</button><button id="mb-hide">—</button></span></header>
<div id="mb-foot">
<button id="mb-toggle">INTERCEPT ON</button>
<button id="mb-forward">FORWARD ALL</button>
<button id="mb-har">HAR</button>
<button id="mb-clear">CLEAR</button>
<span id="mb-count"></span>
</div>
<nav id="mb-list"></nav>`;
D.body.append(icon,panel);

const $ = id => panel.querySelector('#'+id);

function renderOverlay() {
  $('mb-toggle').textContent = 'INTERCEPT ' + (state.enabled?'ON':'OFF');
  $('mb-count').textContent = 'Queue: ' + state.queue.length;
  $('mb-list').innerHTML = state.requests.slice(0,60).map(r =>
    `<button data-id="${r.id}">#${r.id} ${escapeHTML(r.method)} · ${escapeHTML(r.status ?? (r.done?'DONE':'WAIT'))}<br>${escapeHTML(r.url)}</button>`
  ).join('');
}

$('mb-toggle').onclick = () => {
  state.enabled = !state.enabled;
  if (!state.enabled) forwardAll();
  notify();
};
$('mb-forward').onclick = forwardAll;
$('mb-har').onclick = harExport;
$('mb-clear').onclick = () => {
  state.requests = [];
  state.queue = [];
  state.selected = null;
  notify();
};
$('mb-hide').onclick = () => panel.classList.remove('open');
icon.onclick = () => panel.classList.toggle('open');
$('mb-list').onclick = e => {
  const b = e.target.closest('[data-id]');
  if (!b) return;
  state.selected = state.requests.find(r => r.id === Number(b.dataset.id));
  openDashboard();
};
$('mb-open').onclick = openDashboard;

/* DASHBOARD TAB */
function openDashboard() {
  if (dashboard && !dashboard.closed) {
    dashboard.focus();
    renderDashboard();
    return;
  }

  dashboard = W.open('', 'InspectorProDashboard');
  if (!dashboard) {
    alert('Yeni sekme engellendi. Popup iznini etkinleştir.');
    return;
  }

  const d = dashboard.document;
  d.open();
  d.write(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Inspector Pro</title></head><body></body></html>`);
  d.close();

  const css = d.createElement('style');
  css.textContent = `
  *{box-sizing:border-box}body{margin:0;background:#080e19;color:#e5e7eb;font:13px ui-monospace,monospace}
  button,input,textarea,select{font:inherit}button{background:#263449;color:white;border:1px solid #475569;padding:8px 10px;border-radius:5px;cursor:pointer}
  button:hover{background:#34465f}input,textarea,select{background:#020617;color:#d1fae5;border:1px solid #334155;padding:9px;border-radius:5px;min-width:0}
  header{height:54px;background:#111c2e;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid #334155}
  header strong{font-size:16px;color:#60a5fa}.layout{display:grid;grid-template-columns:320px 1fr;height:calc(100vh - 54px)}
  aside{border-right:1px solid #334155;display:flex;flex-direction:column;min-height:0}
  .toolbar,.tabs,.actions{display:flex;gap:6px;flex-wrap:wrap;padding:9px;border-bottom:1px solid #253348}
  #search{width:100%}#requests{overflow:auto;flex:1}
  .req{display:block;width:100%;text-align:left;border:0;border-bottom:1px solid #263449;border-radius:0;background:transparent;overflow-wrap:anywhere}
  .req.active{background:#1e3a5f}.status{color:#86efac}
  main{display:flex;flex-direction:column;min-width:0;min-height:0}
  .tabs button.active{background:#1d4ed8}
  #editor{width:100%;flex:1;resize:none;border:0;border-radius:0;padding:14px;line-height:1.5;min-height:100px}
  .bottom{padding:10px;border-top:1px solid #334155;display:flex;gap:6px;flex-wrap:wrap}
  #status{padding:7px 12px;color:#94a3b8}
  @media(max-width:720px){.layout{grid-template-columns:38% 62%}.req{font-size:11px}.toolbar{padding:5px}button{padding:7px}}
  `;
  d.head.appendChild(css);

  const root = d.createElement('div');
  root.innerHTML = `
  <header><strong>⚡ INSPECTOR PRO</strong><span id="summary">Connecting...</span></header>
  <div class="layout">
    <aside>
      <div class="toolbar">
        <input id="search" placeholder="Filter URL / method / status">
        <button id="toggle">INTERCEPT ON</button><button id="forwardAll">FORWARD ALL</button>
        <button id="har">EXPORT HAR</button><button id="clear">CLEAR</button>
      </div>
      <div id="requests"></div>
    </aside>
    <main>
      <div class="tabs">
        <button data-tab="request" class="active">Request</button>
        <button data-tab="response">Response</button>
        <button data-tab="repeater">Repeater</button>
        <button data-tab="scripts">Script Lab</button>
        <button data-tab="analyzer">Analyzer</button>
      </div>
      <textarea id="editor" spellcheck="false"></textarea>
      <div class="bottom" id="actions">
        <button id="forward">FORWARD</button><button id="drop">DROP</button>
        <button id="replay">REPLAY</button><button id="curl">COPY cURL</button>
        <button id="fetchCopy">COPY FETCH</button><button id="raw">COPY RAW</button>
        <button id="send">SEND</button><button id="download">DOWNLOAD</button>
      </div>
      <div id="status">Ready</div>
    </main>
  </div>`;
  d.body.appendChild(root);

  const q = id => d.getElementById(id);
  let activeTab = 'request';

  function setStatus(s) { q('status').textContent = s; }

  function currentText() {
    const r = state.selected;
    if (!r) return '';
    if (activeTab === 'request') return JSON.stringify({
      url:r.url,method:r.method,headers:r.headers,body:r.body
    },null,2);
    if (activeTab === 'response') return JSON.stringify({
      status:r.status,headers:r.responseHeaders,body:r.responseBody,error:r.error,duration:r.duration
    },null,2);
    if (activeTab === 'repeater') return q('editor').value || JSON.stringify({
      url:r.url,method:r.method,headers:r.headers,body:r.body
    },null,2);
    if (activeTab === 'scripts') return `// Before request: edit request and return it\n${state.before}\n\n// After response: inspect response and return it\n// response.status, response.headers, response.body\n${state.after}`;
    if (activeTab === 'analyzer') return q('editor').value || (r.responseBody || r.body || '');
    return '';
  }

  function renderDashboard() {
    if (!dashboard || dashboard.closed) return;
    const d = dashboard.document;
    const q = id => d.getElementById(id);
    if (!q('requests')) return;

    q('summary').textContent = `${state.requests.length} requests · ${state.queue.length} queued`;
    q('toggle').textContent = 'INTERCEPT ' + (state.enabled?'ON':'OFF');

    const filter = (q('search').value || '').toLowerCase();
    q('requests').innerHTML = state.requests.filter(r =>
      `${r.method} ${r.url} ${r.status || ''}`.toLowerCase().includes(filter)
    ).map(r =>
      `<button class="req ${state.selected===r?'active':''}" data-id="${r.id}">
      <span class="status">#${r.id} ${escapeHTML(r.method)} · ${escapeHTML(r.status ?? (r.done?'DONE':'WAITING'))}</span><br>${escapeHTML(r.url)}
      </button>`
    ).join('');

    if (activeTab !== 'repeater' && activeTab !== 'scripts' && activeTab !== 'analyzer') {
      q('editor').value = currentText();
    }
  }

  function setTab(tab) {
    activeTab = tab;
    q('editor').value = currentText();
    q('editor').placeholder = tab === 'repeater'
      ? 'Edit request JSON and press SEND'
      : tab === 'scripts'
      ? 'Write Before and After JavaScript scripts'
      : tab === 'analyzer'
      ? 'Paste JSON, JWT, Base64, URL encoded text or response'
      : '';
    q('actions').querySelectorAll('button').forEach(b => b.style.display = 'inline-block');
    if (tab === 'request') {
      ['forward','drop','replay','curl','fetchCopy','raw','send','download'].forEach(id=>q(id).style.display='inline-block');
    } else if (tab === 'response') {
      ['forward','drop','replay','curl','fetchCopy','raw','send'].forEach(id=>q(id).style.display='none');
    } else if (tab === 'repeater') {
      ['forward','drop','replay','curl','fetchCopy','raw'].forEach(id=>q(id).style.display='none');
      q('send').style.display='inline-block';
      q('download').style.display='none';
    } else if (tab === 'scripts') {
      
      ['forward','drop','replay','curl','fetchCopy','raw','send'].forEach(id=>q(id).style.display='none');
      q('download').textContent='SAVE SCRIPTS';
    } else if (tab === 'analyzer') {
      ['forward','drop','replay','curl','fetchCopy','raw','send'].forEach(id=>q(id).style.display='none');
      q('download').textContent='FORMAT / DECODE';
    }

    q('download').style.display = ['scripts','analyzer','request','response'].includes(tab) ? 'inline-block' : 'none';

    if (tab === 'scripts') q('download').textContent='SAVE SCRIPTS';
    if (tab === 'analyzer') q('download').textContent='FORMAT / DECODE';
    if (tab === 'request' || tab === 'response') q('download').textContent='DOWNLOAD';

    [...d.querySelectorAll('[data-tab]')].forEach(b => {
      b.classList.toggle('active',b.dataset.tab===tab);
    });
  }

  d.querySelectorAll('[data-tab]').forEach(b => {
    b.onclick = () => setTab(b.dataset.tab);
  });

  q('requests').onclick = e => {
    const b = e.target.closest('[data-id]');
    if (!b) return;

    state.selected = state.requests.find(r=>r.id===Number(b.dataset.id));
    setTab(activeTab === 'repeater' ? 'repeater' : 'request');
    renderDashboard();
  };

  q('search').oninput = renderDashboard;

  q('toggle').onclick = () => {
    state.enabled = !state.enabled;
    if (!state.enabled) forwardAll();
    renderDashboard();
    notify();
  };

  q('forwardAll').onclick = forwardAll;
  q('har').onclick = harExport;

  q('clear').onclick = () => {
    state.requests = [];
    state.queue = [];
    state.selected = null;
    q('editor').value = '';
    renderDashboard();
  };

  q('forward').onclick = () => {
    const r = state.selected;
    if (!r || r.done) return;

    try {
      const v = JSON.parse(q('editor').value);

      if (!v.url || !v.method) throw Error('URL ve Method gerekli');

      Object.assign(r,{
        url:v.url,
        method:v.method.toUpperCase(),
        headers:v.headers || {},
        body:v.body || ''
      });

      dispatch(r);
      setStatus('Request forwarded');
    } catch(e) {
      setStatus('JSON error: '+e.message);
    }
  };

  q('drop').onclick = () => {
    const r = state.selected;
    if (!r || r.done) return;

    r.dropped = true;
    r.done = true;
    r.error = 'Dropped by user';

    state.queue = state.queue.filter(x=>x!==r);
    r.cancel?.();

    setStatus('Request dropped');
    renderDashboard();
  };

  q('replay').onclick = () => {
    replay(state.selected);
    setStatus('Request replayed');
  };

  q('curl').onclick = async () => {
    if (!state.selected) return;
    try {
      await dashboard.navigator.clipboard.writeText(toCurl(state.selected));
      setStatus('cURL copied');
    } catch(e) {
      setStatus('Clipboard error: '+e.message);
    }
  };

  q('fetchCopy').onclick = async () => {
    if (!state.selected) return;
    try {
      await dashboard.navigator.clipboard.writeText(toFetch(state.selected));
      setStatus('Fetch copied');
    } catch(e) {
      setStatus('Clipboard error: '+e.message);
    }
  };

  q('raw').onclick = async () => {
    if (!state.selected) return;
    try {
      await dashboard.navigator.clipboard.writeText(requestText(state.selected));
      setStatus('Raw request copied');
    } catch(e) {
      setStatus('Clipboard error: '+e.message);
    }
  };

  q('send').onclick = async () => {
    try {
      const v = JSON.parse(q('editor').value);

      if (!v.url) throw Error('URL gerekli');

      const r = add({
        type:'repeater',
        url:v.url,
        method:String(v.method || 'GET').toUpperCase(),
        headers:v.headers || {},
        body:v.body || '',
        send:manualSend
      });

      state.selected = r;
      setStatus('Request sending...');

      await dispatch(r);

      setTab('response');
      renderDashboard();
      setStatus('Request completed');
    } catch(e) {
      setStatus('Request error: '+e.message);
    }
  };

  q('download').onclick = () => {
    if (activeTab === 'scripts') {
      const text = q('editor').value;
      const marker = '// After response:';
      const index = text.indexOf(marker);

      if (index < 0) {
        setStatus('After response marker bulunamadı');
        return;
      }

      const beforePart = text.slice(0,index);
      const afterPart = text.slice(index + marker.length);

      state.before = beforePart
        .replace('// Before request: edit request and return it','')
        .trim();

      state.after = afterPart
        .replace('// response.status, response.headers, response.body','')
        .trim();

      setStatus('Scripts saved');
      return;
    }

    if (activeTab === 'analyzer') {
      const text = q('editor').value.trim();
      let output = text;

      try {
        output = JSON.stringify(JSON.parse(text),null,2);
      } catch {
        try {
          const jwt = text.split('.');
          if (
            jwt.length === 3 &&
            /^[A-Za-z0-9_-]+$/.test(jwt[1])
          ) {
            let payload = jwt[1]
              .replace(/-/g,'+')
              .replace(/_/g,'/');

            payload += '='.repeat((4-payload.length%4)%4);

            output = JSON.stringify(
              JSON.parse(atob(payload)),
              null,
              2
            );
          } else if (/^[A-Za-z0-9+/]+=*$/.test(text)) {
            output = atob(text);
          } else if (/%[0-9A-F]{2}/i.test(text)) {
            output = decodeURIComponent(text);
          }
        } catch(e) {
          output = 'Decode error: '+e.message;
        }
      }

      q('editor').value = output;
      setStatus('Formatted / decoded');
      return;
    }

    saveFile(
      'inspector-selection.txt',
      q('editor').value,
      'text/plain'
    );

    setStatus('File exported');
  };

  setTab('request');
  renderDashboard();
}

/* DASHBOARD API */
W.__miniBurp = {
  show:() => {
    panel.classList.add('open');
    renderOverlay();
  },

  openTab:openDashboard,
  exportHAR:harExport,

  getRequests:() => state.requests,

  send:async req => manualSend(req),

  destroy:() => {
    W.fetch = originalFetch;
    X.open = originalOpen;
    X.send = originalSend;
    X.setRequestHeader = originalHeader;

    icon.remove();
    panel.remove();
    style.remove();

    try {
      if (dashboard && !dashboard.closed) dashboard.close();
    } catch {}

    delete W.__miniBurp;
  }
};

renderOverlay();
panel.classList.add('open');

})();
       
