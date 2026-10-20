/* Runs in the actual same-origin viewer document. Key remains in its memory. */
(() => {
  'use strict';
  const bridgeURL = new URL(document.currentScript.src);
  const origin = bridgeURL.origin;
  const shellVersion = '20261020-mobile4';
  const workerScript = new URL('gate-sw.js', bridgeURL);
  if(bridgeURL.searchParams.has('v'))workerScript.searchParams.set('v',bridgeURL.searchParams.get('v'));
  const workerURL = workerScript.href;
  if (window.parent === window) return;
  let key = null, manifest = null, release = null, issuedAt = 0;
  let installing = null, expiryTimer = null, locked = false;
  let rendered = false, pendingHTML = null, retryTimer = null;
  const pendingRPCs = new Set();
  const RPC_TIMEOUT_MS = 12000;
  const MAX_INSTALL_ATTEMPTS = 3;
  const tellParent = (type, message, code) => window.parent.postMessage({type, ...(message ? {message} : {}), ...(code ? {code} : {})}, origin);
  const failure = code => Object.assign(new Error(code), {code});
  function ownController() {
    return new Promise((resolve, reject) => {
      const container = navigator.serviceWorker;
      const cleanup = () => { clearTimeout(timer); clearInterval(poll); container.removeEventListener('controllerchange', check); };
      const check = () => {
        const worker = container.controller;
        if (worker?.scriptURL === workerURL) { cleanup(); resolve(worker); }
      };
      const timer = setTimeout(() => { cleanup(); reject(failure('CONTROLLER_TIMEOUT')); }, 30000);
      const poll = setInterval(check, 250);
      container.addEventListener('controllerchange', check);check();
    });
  }
  const rpc = async (type, fields = {}, portTransport = true) => {
    const worker = await ownController();
    // A lock can arrive while this new document is waiting to be controlled.
    // Never install a captured key after that authority has been forgotten.
    if (type === 'REPLAY_INSTALL_SESSION' && (locked || !key || fields.key !== key || fields.issuedAt !== issuedAt)) {
      throw failure('SESSION_CANCELLED');
    }
    return new Promise((resolve, reject) => {
      const requestId = [...crypto.getRandomValues(new Uint8Array(16))].map(n=>n.toString(16).padStart(2,'0')).join('');
      const channel = portTransport ? new MessageChannel() : null;
      let settled = false;
      const finish = (result, error) => {
        if(settled)return;settled=true;
        clearTimeout(timer);channel?.port1.close();
        navigator.serviceWorker.removeEventListener('message', onReply);
        navigator.serviceWorker.removeEventListener('controllerchange', onControllerChange);
        pendingRPCs.delete(cancel);
        if(error)reject(error);
        else if(result?.ok)resolve(result);
        else reject(failure('SESSION_INVALID'));
      };
      const onReply = event => {
        if(event.source?.scriptURL!==workerURL || navigator.serviceWorker.controller?.scriptURL!==workerURL ||
            event.data?.type!=='REPLAY_SESSION_REPLY' || event.data.requestId!==requestId)return;
        finish(event.data.result);
      };
      // A replacement controller needs its own install; never wait on an old worker's ACK.
      const onControllerChange = () => finish(null, failure('CONTROLLER_CHANGED'));
      const cancel = () => finish(null, failure('SESSION_CANCELLED'));
      const timer = setTimeout(() => finish(null, failure('SESSION_TIMEOUT')), RPC_TIMEOUT_MS);
      pendingRPCs.add(cancel);
      navigator.serviceWorker.addEventListener('message', onReply);
      navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);
      navigator.serviceWorker.startMessages?.();
      if(channel){channel.port1.onmessage = event => finish(event.data);channel.port1.start();}
      try {worker.postMessage({type, ...fields, requestId}, channel ? [channel.port2] : []);}
      catch(error) {finish(null, failure(error.name==='DataCloneError'?'SESSION_INVALID':'CONTROLLER_TIMEOUT'));}
    });
  };
  function forget() {
    locked = true; key = null; manifest = null; release = null; issuedAt = 0;
    pendingHTML = null;clearTimeout(expiryTimer);
    for(const cancel of [...pendingRPCs])cancel();
    // Release a pending backoff immediately, so a lock cannot leave a retry alive.
    if(retryTimer){clearTimeout(retryTimer.id);retryTimer.resolve();retryTimer=null;}
  }
  async function lock(notify = true) {
    forget();
    try { await rpc('REPLAY_REVOKE_SESSION'); } catch (_) { /* Removing the iframe also ends its client authority. */ }
    if (notify) tellParent('REPLAY_LOCKED');
  }
  async function install() {
    if (!key || locked) return;
    if (installing) return installing;
    installing = (async () => {
      try {
        for(let trial=0;trial<MAX_INSTALL_ATTEMPTS;trial++){
          if(locked || !key)return false;
          try {
            // The retry also omits transferable ports: a broken port delivery
            // path must not prevent the native client from receiving its reply.
            await rpc('REPLAY_INSTALL_SESSION', {key, manifest, release, issuedAt}, trial===0);
            if(locked)return false;
            tellParent('REPLAY_UNLOCKED');
            // Every successful recovery completes the original opening operation.
            // Later controller/NEED_KEY events must not leave an empty document.
            if(pendingHTML && !rendered){
              const html=pendingHTML;pendingHTML=null;
              render(html).catch(()=>{if(!locked)tellParent('REPLAY_RESOURCE_ERROR');});
            }
            return true;
          } catch(error) {
            if(locked || error.code==='SESSION_CANCELLED')return false;
            if(!['SESSION_TIMEOUT','CONTROLLER_TIMEOUT','CONTROLLER_CHANGED'].includes(error.code)){
              forget();tellParent('REPLAY_ERROR', null, 'SESSION_INVALID');return false;
            }
            if(trial===MAX_INSTALL_ATTEMPTS-1){
              tellParent('REPLAY_RETRYABLE_ERROR', null, error.code);return false;
            }
            tellParent('REPLAY_RECONNECTING', null, error.code);
            await new Promise(resolve=>{
              retryTimer={resolve,id:setTimeout(()=>{retryTimer=null;resolve();},500*(trial+1))};
            });
          }
        }
      } finally { installing = null; }
    })();
    return installing;
  }
  async function render(html) {
    if(rendered || locked)return;
    if(typeof html!=='string' || html.length>1024*1024)throw new Error('Invalid document');
    const parsed=new DOMParser().parseFromString(html,'text/html');
    const base=parsed.querySelector('base');
    if(base?.href!==new URL('view/',bridgeURL).href)throw new Error('Invalid document base');
    // DOM replacement keeps the real document URL and its native client ID.
    // Scripts are installed only after this document's own session is ready.
    const scripts=[...parsed.querySelectorAll('script')].map(node=>{
      const result={attributes:[...node.attributes].map(a=>[a.name,a.value]),text:node.textContent};
      node.remove();return result;
    });
    rendered=true;
    document.documentElement.lang=parsed.documentElement.lang||'zh-CN';
    document.head.replaceChildren(...[...parsed.head.childNodes].map(node=>document.importNode(node,true)));
    document.body.replaceChildren(...[...parsed.body.childNodes].map(node=>document.importNode(node,true)));
    for(const source of scripts) {
      if(locked)return;
      await new Promise((resolve,reject)=>{
        const script=document.createElement('script');
        for(const [name,value] of source.attributes)if(name!=='defer'&&name!=='async')script.setAttribute(name,value);
        script.async=false;script.textContent=source.text;
        if(script.src){script.onload=resolve;script.onerror=()=>reject(new Error('Resource unavailable'));}
        document.head.append(script);
        if(!script.src)resolve();
      });
    }
    if(!locked)tellParent('REPLAY_VIEW_READY');
  }
  window.addEventListener('message', event => {
    if (event.source !== window.parent || event.origin !== origin) return;
    if (event.data?.type === 'REPLAY_UNLOCK') {
      if (key || installing) return;
      const incoming = event.data;
      if (!incoming.key || incoming.key.extractable !== false || incoming.key.algorithm?.name !== 'AES-GCM') {
        tellParent('REPLAY_ERROR', null, 'SESSION_INVALID'); return;
      }
      key = incoming.key; manifest = incoming.manifest; release = incoming.release;
      pendingHTML = incoming.html;
      issuedAt = Number.isSafeInteger(incoming.issuedAt) ? incoming.issuedAt : Date.now(); locked = false;
      expiryTimer = setTimeout(() => lock(), Math.max(0, issuedAt + 12 * 60 * 60 * 1000 - Date.now()));
      install();
    } else if (event.data?.type === 'REPLAY_LOCK') lock();
  });
  navigator.serviceWorker.addEventListener('message', event => {
    // WebKit may expose different wrappers for the same worker. Never send a
    // key to event.source: RPC always targets this document's verified controller.
    if (event.source?.scriptURL !== workerURL || navigator.serviceWorker.controller?.scriptURL !== workerURL) return;
    if (event.data?.type === 'REPLAY_NEED_KEY') install();
    else if (event.data?.type === 'REPLAY_SESSION_EXPIRED') { forget(); tellParent('REPLAY_LOCKED'); }
    else if (event.data?.type === 'REPLAY_RESOURCE_ERROR') tellParent('REPLAY_RESOURCE_ERROR');
    else if (event.data?.type === 'REPLAY_CONTENT_ERROR') tellParent('REPLAY_ERROR', null, 'CONTENT_INVALID');
  });
  navigator.serviceWorker.addEventListener('controllerchange', () => { if (key && !locked) install(); });
  navigator.serviceWorker.startMessages?.();
  window.addEventListener('pagehide', () => { forget(); navigator.serviceWorker.controller?.postMessage({type: 'REPLAY_REVOKE_SESSION'}); });
  window.parent.postMessage({type:'REPLAY_BRIDGE_READY',version:shellVersion},origin);
})();
