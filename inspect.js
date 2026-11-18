
(() => {
'use strict';

if(window.__miniBurp?.destroy){
 window.__miniBurp.show();
 return;
}

const originalFetch=window.fetch;
const X=XMLHttpRequest.prototype;
const originalOpen=X.open;
const originalSend=X.send;
const originalHeader=X.setRequestHeader;

const state={
 enabled:true,
 requests:[],
 queue:[],
 selected:null,
 id:0
};

const style=document.createElement('style');
style.textContent=`
#mb-icon{position:fixed;right:15px;bottom:15px;width:50px;height:50px;border-radius:50%;background:#2563eb;color:white;z-index:2147483647;border:0;font-weight:bold;touch-action:none}
#mb-panel{position:fixed;z-index:2147483646;right:10px;bottom:75px;width:min(760px,96vw);height:min(650px,85dvh);background:#0b1220;color:white;border:1px solid #475569;border-radius:12px;display:none;flex-direction:column;overflow:hidden;font:12px monospace;box-shadow:0 10px 40px #000}
#mb-panel.open{display:flex}
#mb-panel.max{left:5px!important;top:5px!important;right:5px!important;bottom:5px!important;width:auto!important;height:auto!important}
#mb-panel button{background:#263449;color:white;border:1px solid #475569;padding:7px;border-radius:5px}
#mb-head{background:#172338;padding:10px;display:flex;justify-content:space-between;touch-action:none}
#mb-tools,#mb-actions,#mb-tabs{display:flex;gap:5px;padding:8px;flex-wrap:wrap}
#mb-main{display:grid;grid-template-columns:32% 68%;flex:1;min-height:0}
#mb-list{overflow:auto;border-right:1px solid #475569}
#mb-list button{display:block;width:100%;text-align:left;border:0;border-bottom:1px solid #334155;overflow-wrap:anywhere}
#mb-editor{flex:1;min-height:0;resize:none;background:#020617;color:#86efac;border:0;padding:10px;font:11px monospace}
#mb-detail{display:flex;flex-direction:column;min-width:0;min-height:0}
#mb-filter{flex:1;min-width:0;background:#020617;color:white;padding:7px}
@media(max-width:600px){
#mb-panel{left:5px!important;right:5px!important;width:auto!important;height:75dvh!important}
#mb-main{grid-template-columns:30% 70%}
}
`;
document.head.appendChild(style);

const icon=document.createElement('button');
icon.id='mb-icon';
icon.textContent='MB';

const panel=document.createElement('div');
panel.id='mb-panel';

panel.innerHTML=`
<header id="mb-head">
<b>⚡ MINI BURP</b>
<span>
<button id="mb-max">□</button>
<button id="mb-hide">—</button>
<button id="mb-close">×</button>
</span>
</header>

<div id="mb-tools">
<button id="mb-toggle">INTERCEPT ON</button>
<input id="mb-filter" placeholder="URL filtrele">
<button id="mb-clear">CLEAR</button>
<span id="mb-count"></span>
</div>

<main id="mb-main">
<nav id="mb-list"></nav>

<section id="mb-detail">
<div id="mb-tabs">
<button data-view="request">Request</button>
<button data-view="response">Response</button>
<button data-view="info">Info</button>
</div>

<textarea id="mb-editor" spellcheck="false"></textarea>

<div id="mb-actions">
<button id="mb-forward">FORWARD</button>
<button id="mb-drop">DROP</button>
<button id="mb-replay">REPLAY</button>
<button id="mb-copy">COPY</button>
</div>
</section>
</main>
`;

document.body.append(icon,panel);

const $=id=>panel.querySelector('#'+id);
const safe=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function render(){
 $('mb-toggle').textContent='INTERCEPT '+(state.enabled?'ON':'OFF');
 $('mb-count').textContent='Queue: '+state.queue.length;

 const filter=$('mb-filter').value.toLowerCase();

 $('mb-list').innerHTML=state.requests
 .filter(r=>(r.method+' '+r.url).toLowerCase().includes(filter))
 .map(r=>`<button data-id="${r.id}">
 ${safe(r.method)} · ${safe(r.status??(r.done?'DONE':'WAITING'))}
 <br>${safe(r.url)}
 </button>`).join('');

}

function show(r,view='request'){
 state.selected=r;
 state.view=view;

 if(view==='request'){
 $('mb-editor').value=JSON.stringify({
 url:r.url,
 method:r.method,
 headers:r.headers,
 body:r.body
 },null,2);
 }

 if(view==='response'){
 $('mb-editor').value=JSON.stringify({
 status:r.status,
 headers:r.responseHeaders,
 body:r.responseBody,
 error:r.error
 },null,2);
 }

 if(view==='info'){
 $('mb-editor').value=JSON.stringify({
 id:r.id,
 type:r.type,
 state:r.done?'completed':'waiting',
 url:r.url
 },null,2);
 }

 render();
}

function add(r){
 r.id=++state.id;
 r.created=new Date().toISOString();
 state.requests.unshift(r);
 state.selected=r;

 if(state.enabled)state.queue.push(r);
 else dispatch(r);

 show(r);
}

function dispatch(r){
 if(!r||r.done||r.dropped||r.started)return;

 r.started=Date.now();
 state.queue=state.queue.filter(x=>x!==r);
 render();

 Promise.resolve()
 .then(()=>r.send(r))
 .then(result=>{
  r.status=result.status;
  r.responseHeaders=result.headers||{};
  r.responseBody=result.body||'';
  r.done=true;
  r.duration=Date.now()-r.started;
  if(state.selected===r)show(r,'response');
 })
 .catch(e=>{
  r.error=String(e);
  r.done=true;
  if(state.selected===r)show(r,'response');
 })
 .finally(render);
}

$('mb-list').onclick=e=>{
 const b=e.target.closest('[data-id]');
 if(!b)return;
 const r=state.requests.find(x=>x.id===Number(b.dataset.id));
 if(r)show(r);
};

panel.querySelectorAll('[data-view]').forEach(b=>{
 b.onclick=()=>state.selected&&show(state.selected,b.dataset.view);
});

$('mb-toggle').onclick=()=>{
 state.enabled=!state.enabled;

 if(!state.enabled){
  const pending=[...state.queue];
  state.queue=[];
  pending.forEach(dispatch);
 }
 render();
};

$('mb-forward').onclick=()=>{
 const r=state.selected;
 if(!r||r.done||r.dropped)return;

 try{
  const data=JSON.parse($('mb-editor').value);
  if(!data.url||!data.method)throw Error('URL ve Method gerekli');

  r.url=data.url;
  r.method=data.method;
  r.headers=data.headers||{};
  r.body=data.body??'';

  dispatch(r);
 }catch(e){
  alert('JSON hatası: '+e.message);
 }
};

$('mb-drop').onclick=()=>{
 const r=state.selected;
 if(!r||r.done)return;

 r.dropped=true;
 r.done=true;
 r.error='Request dropped';
 state.queue=state.queue.filter(x=>x!==r);
 r.cancel?.();
 show(r,'info');
};

$('mb-replay').onclick=()=>{
 const r=state.selected;
 if(!r)return;

 const copy={
  ...r,
  id:undefined,
  done:false,
  dropped:false,
  started:null,
  status:null,
  responseBody:null,
  error:null,
  headers:{...r.headers}
 };

 add(copy);
};

$('mb-clear').onclick=()=>{
 state.requests=[];
 state.queue=[];
 state.selected=null;
 $('mb-editor').value='';
 render();
};

$('mb-filter').oninput=render;

$('mb-copy').onclick=()=>{
 navigator.clipboard?.writeText($('mb-editor').value);
};

$('mb-max').onclick=()=>{
 panel.classList.toggle('max');
};

$('mb-hide').onclick=()=>{
 panel.classList.remove('open');
};

$('mb-close').onclick=()=>{
 window.__miniBurp.destroy();
};

icon.onclick=()=>panel.classList.toggle('open');

window.fetch=function(input,init={}){
 const req=input instanceof Request?input:null;
 const url=req?req.url:String(input);
 const method=(init.method||req?.method||'GET').toUpperCase();
 const headers=Object.fromEntries(new Headers(init.headers||req?.headers||{}));
 const bodyPromise=init.body!==undefined
 ?Promise.resolve(init.body)
 :req?req.clone().text():Promise.resolve('');

 return bodyPromise.then(body=>new Promise((resolve,reject)=>{
  const r={
   type:'fetch',
   url,method,headers,body:body??'',
   done:false,
   cancel:()=>reject(new DOMException('Dropped','AbortError')),

   send:async edited=>{
    const options={
     method:edited.method,
     headers:edited.headers,
     credentials:req?.credentials,
     mode:req?.mode,
     cache:req?.cache,
     redirect:req?.redirect,
     signal:init.signal||req?.signal
    };

    if(!['GET','HEAD'].includes(edited.method)&&edited.body!=='')
     options.body=edited.body;

    const response=await originalFetch(edited.url,options);
    const copy=response.clone();
    const text=await copy.text().catch(()=>'Response unavailable');

    resolve(response);

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

const xhrMeta=new WeakMap();

X.open=function(method,url,...args){
 xhrMeta.set(this,{
  method:String(method).toUpperCase(),
  url:String(url),
  args,
  headers:{}
 });
 return originalOpen.call(this,method,url,...args);
};

X.setRequestHeader=function(k,v){
 const meta=xhrMeta.get(this);
 if(meta){
  meta.headers[k]=String(v);
  return;
 }
 return originalHeader.call(this,k,v);
};

X.send=function(body){
 const xhr=this;
 const meta=xhrMeta.get(xhr)||{
  method:'GET',url:'',args:[],headers:{}
 };

 const r={
  type:'xhr',
  url:meta.url,
  method:meta.method,
  headers:{...meta.headers},
  body:body==null?'':String(body),
  done:false,

  cancel:()=>{try{originalAbort.call(xhr)}catch{}},

  send:edited=>new Promise((resolve,reject)=>{
   try{
    originalOpen.call(xhr,edited.method,edited.url,...meta.args);

    Object.entries(edited.headers||{}).forEach(([k,v])=>{
     originalHeader.call(xhr,k,String(v));
    });

    xhr.addEventListener('loadend',()=>{
     let responseBody='';
     try{
      responseBody=xhr.responseType===''||xhr.responseType==='text'
      ?xhr.responseText:'Response type: '+xhr.responseType;
     }catch{}

     const headers={};
     try{
      xhr.getAllResponseHeaders().trim().split(/[\r\n]+/).forEach(line=>{
       const i=line.indexOf(':');
       if(i>0)headers[line.slice(0,i).trim()]=line.slice(i+1).trim();
      });
     }catch{}

     resolve({
      status:xhr.status,
      headers,
      body:responseBody
     });
    },{once:true});

    xhr.addEventListener('error',()=>reject(Error('Network error')),{once:true});
    xhr.addEventListener('abort',()=>reject(Error('Aborted')),{once:true});

    originalSend.call(xhr,edited.body||null);
   }catch(e){reject(e)}
  })
 };

 add(r);
};

let drag=null;

$('mb-head').onpointerdown=e=>{
 if(e.target.closest('button')||panel.classList.contains('max'))return;
 const rect=panel.getBoundingClientRect();
 drag={x:e.clientX-rect.left,y:e.clientY-rect.top};
 $('mb-head').setPointerCapture(e.pointerId);
};

$('mb-head').onpointermove=e=>{
 if(!drag)return;
 panel.style.left=Math.max(0,e.clientX-drag.x)+'px';
 panel.style.top=Math.max(0,e.clientY-drag.y)+'px';
 panel.style.right='auto';
 panel.style.bottom='auto';
};

$('mb-head').onpointerup=()=>drag=null;

let iconDrag=null;
icon.onpointerdown=e=>{
 iconDrag={x:e.clientX-icon.offsetLeft,y:e.clientY-icon.offsetTop,moved:false};
 icon.setPointerCapture(e.pointerId);
};

icon.onpointermove=e=>{
 if(!iconDrag)return;
 if(Math.abs(e.movementX)+Math.abs(e.movementY)>2)iconDrag.moved=true;
 if(iconDrag.moved){
  icon.style.left=Math.max(0,e.clientX-iconDrag.x)+'px';
  icon.style.top=Math.max(0,e.clientY-iconDrag.y)+'px';
  icon.style.right='auto';
  icon.style.bottom='auto';
 }
};

icon.onpointerup=()=>iconDrag=null;

window.__miniBurp={
 show:()=>panel.classList.add('open'),
 destroy:()=>{
  window.fetch=originalFetch;
  X.open=originalOpen;
  X.send=originalSend;
  X.setRequestHeader=originalHeader;
  icon.remove();
  panel.remove();
  style.remove();
  delete window.__miniBurp;
 }
};

render();
})();
   
