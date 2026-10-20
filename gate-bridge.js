/* Runs in the actual same-origin viewer document. Key remains in its memory. */
(() => {
  'use strict';
  const bridgeURL = new URL(document.currentScript.src);
  const origin = bridgeURL.origin;
  const shellVersion = '20261020-mobile5';
  const workerScript = new URL('gate-sw.js', bridgeURL);
  if(bridgeURL.searchParams.has('v'))workerScript.searchParams.set('v',bridgeURL.searchParams.get('v'));
  const workerURL = workerScript.href;
  if (window.parent === window) return;
  let key = null, manifest = null, release = null, issuedAt = 0;
  let installing = null, expiryTimer = null, locked = false;
  let rendered = false, pendingHTML = null, retryTimer = null;
  let keyEnvelope = null, useByteTransport = false;
  const pendingRPCs = new Set();
  const RPC_TIMEOUT_MS = 12000;
  const MAX_INSTALL_ATTEMPTS = 3;
  const tellParent = (type, message, code) => window.parent.postMessage({type, ...(message ? {message} : {}), ...(code ? {code} : {})}, origin);
  const failure = code => Object.assign(new Error(code), {code});
  const randomId = () => [...crypto.getRandomValues(new Uint8Array(16))].map(n=>n.toString(16).padStart(2,'0')).join('');
  async function sessionProof(authority, originalIssuedAt) {
    if(locked || key!==authority || issuedAt!==originalIssuedAt)return false;
    if(navigator.serviceWorker.controller?.scriptURL!==workerURL)return false;
    tellParent('REPLAY_PHASE', null, 'status_check');
    const requestId=randomId(),url=new URL('view/__session_status',bridgeURL);
    url.searchParams.set('requestId',requestId);
    const controller=new AbortController(),cancel=()=>controller.abort();
    pendingRPCs.add(cancel);
    const timeout=setTimeout(cancel,4000);
    try {
      const response=await fetch(url,{cache:'no-store',credentials:'omit',mode:'same-origin',redirect:'error',signal:controller.signal});
      if(response.status!==200 || !response.headers.get('Content-Type')?.includes('application/json'))return false;
      const proof=await response.json();
      return !locked && key===authority && issuedAt===originalIssuedAt &&
        navigator.serviceWorker.controller?.scriptURL===workerURL &&
        proof.ok===true && proof.requestId===requestId && proof.version===shellVersion &&
        proof.release===release && proof.issuedAt===issuedAt &&
        proof.expiresAt===issuedAt+12*60*60*1000 && Date.now()<proof.expiresAt;
    } catch (_) {return false;}
    finally {clearTimeout(timeout);pendingRPCs.delete(cancel);}
  }
  async function installFields(authority) {
    const fields={manifest,release,issuedAt};
    if(!useByteTransport || !keyEnvelope)return {...fields,key:authority};
    const envelope=keyEnvelope;
    const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:envelope.iv,
      additionalData:new TextEncoder().encode(`football-sealed-v1\n${release}\nsession-key`)},envelope.key,envelope.cipher);
    if(locked || key!==authority || keyEnvelope!==envelope || fields.issuedAt!==issuedAt || raw.byteLength!==32){
      new Uint8Array(raw).fill(0);throw failure('SESSION_CANCELLED');
    }
    return {...fields,keyBytes:raw};
  }
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
    const authority=key;
    const worker = await ownController();
    // A lock can arrive while this new document is waiting to be controlled.
    // Never install a captured key after that authority has been forgotten.
    if (type === 'REPLAY_INSTALL_SESSION' && (locked || !key || authority !== key || fields.issuedAt !== issuedAt)) {
      throw failure('SESSION_CANCELLED');
    }
    return new Promise((resolve, reject) => {
      const requestId = randomId();
      const channel = portTransport ? new MessageChannel() : null;
      let settled = false;
      const finish = (result, error) => {
        if(settled)return;settled=true;
        clearTimeout(timer);channel?.port1.close();
        navigator.serviceWorker.removeEventListener('message', onReply);
        navigator.serviceWorker.removeEventListener('messageerror', onMessageError);
        navigator.serviceWorker.removeEventListener('controllerchange', onControllerChange);
        pendingRPCs.delete(cancel);
        if(error)reject(error);
        else if(result?.ok)resolve(result);
        else reject(failure(['CLIENT_LOOKUP_TIMEOUT','CLIENT_UNAVAILABLE'].includes(result?.code)?result.code:'SESSION_INVALID'));
      };
      const onReply = event => {
        if(event.source?.scriptURL!==workerURL || navigator.serviceWorker.controller?.scriptURL!==workerURL)return;
        if(event.data?.type==='REPLAY_TRANSFER_ERROR' && type==='REPLAY_INSTALL_SESSION'){
          finish(null,failure('KEY_TRANSFER_FAILED'));return;
        }
        if(event.data?.requestId!==requestId)return;
        if(event.data.type==='REPLAY_SESSION_PROGRESS'){
          if(['received','client_lookup','key_import','installed'].includes(event.data.stage))tellParent('REPLAY_PHASE',null,event.data.stage);
        } else if(event.data.type==='REPLAY_SESSION_REPLY')finish(event.data.result);
      };
      const onMessageError = event => {
        if(event.source?.scriptURL===workerURL)finish(null,failure('KEY_TRANSFER_FAILED'));
      };
      // A replacement controller needs its own install; never wait on an old worker's ACK.
      const onControllerChange = () => finish(null, failure('CONTROLLER_CHANGED'));
      const cancel = () => finish(null, failure('SESSION_CANCELLED'));
      const timer = setTimeout(() => finish(null, failure('SESSION_TIMEOUT')), RPC_TIMEOUT_MS);
      pendingRPCs.add(cancel);
      navigator.serviceWorker.addEventListener('message', onReply);
      navigator.serviceWorker.addEventListener('messageerror', onMessageError);
      navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);
      navigator.serviceWorker.startMessages?.();
      if(channel){
        channel.port1.onmessage = event => finish(event.data);
        channel.port1.onmessageerror = () => finish(null,failure('KEY_TRANSFER_FAILED'));
        channel.port1.start();
      }
      const transfer=channel?[channel.port2]:[];
      if(fields.keyBytes)transfer.push(fields.keyBytes);
      try {worker.postMessage({type, ...fields, requestId}, transfer);}
      catch(error) {
        // A failed clone can leave the transfer buffer attached. Erase it before
        // checking session status or waiting for a retry.
        if(fields.keyBytes?.byteLength)new Uint8Array(fields.keyBytes).fill(0);
        finish(null, failure(error.name==='DataCloneError'?'KEY_TRANSFER_FAILED':'CONTROLLER_TIMEOUT'));
      }
    });
  };
  function forget() {
    locked = true; key = null; manifest = null; release = null; issuedAt = 0;
    keyEnvelope=null;
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
          const authority=key,originalIssuedAt=issuedAt;
          let fields;
          try {
            // The retry also omits transferable ports: a broken port delivery
            // path must not prevent the native client from receiving its reply.
            fields=await installFields(authority);
            await rpc('REPLAY_INSTALL_SESSION', fields, trial===0);
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
            if(!['SESSION_TIMEOUT','CONTROLLER_TIMEOUT','CONTROLLER_CHANGED','KEY_TRANSFER_FAILED','CLIENT_LOOKUP_TIMEOUT','CLIENT_UNAVAILABLE'].includes(error.code)){
              forget();tellParent('REPLAY_ERROR', null, 'SESSION_INVALID');return false;
            }
            // Fetch confirmation is independently bound by the worker to this
            // native client. A lost messaging ACK does not mean installation failed.
            if(['SESSION_TIMEOUT','KEY_TRANSFER_FAILED'].includes(error.code) && await sessionProof(authority,originalIssuedAt)){
              tellParent('REPLAY_UNLOCKED');
              if(pendingHTML && !rendered){
                const html=pendingHTML;pendingHTML=null;
                render(html).catch(()=>{if(!locked)tellParent('REPLAY_RESOURCE_ERROR');});
              }
              return true;
            }
            if(locked || key!==authority)return false;
            if(['SESSION_TIMEOUT','KEY_TRANSFER_FAILED'].includes(error.code) && keyEnvelope)useByteTransport=true;
            if(trial===MAX_INSTALL_ATTEMPTS-1){
              tellParent('REPLAY_RETRYABLE_ERROR', null, error.code);return false;
            }
            tellParent('REPLAY_RECONNECTING', null, error.code);
            await new Promise(resolve=>{
              retryTimer={resolve,id:setTimeout(()=>{retryTimer=null;resolve();},500*(trial+1))};
            });
          } finally {
            // A successful transfer detaches this buffer. Failed transfers still
            // leave local bytes, which must be cleared on every path.
            if(fields?.keyBytes?.byteLength)new Uint8Array(fields.keyBytes).fill(0);
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
    tellParent('REPLAY_PHASE',null,'render');
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
      const envelope=incoming.keyEnvelope;
      if(envelope){
        if(envelope.key?.extractable!==false || envelope.key?.algorithm?.name!=='AES-GCM' ||
            envelope.iv?.byteLength!==12 || envelope.cipher?.byteLength!==48){
          forget();tellParent('REPLAY_ERROR',null,'SESSION_INVALID');return;
        }
        keyEnvelope=envelope;
      }
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
