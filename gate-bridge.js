/* Runs in the actual same-origin viewer document. Key remains in its memory. */
(() => {
  'use strict';
  const bridgeURL = new URL(document.currentScript.src);
  const origin = bridgeURL.origin;
  const workerURL = new URL('gate-sw.js', bridgeURL).href;
  if (window.parent === window) return;
  let key = null, manifest = null, release = null, issuedAt = 0;
  let installing = null, expiryTimer = null, locked = false;
  let rendered = false;
  const tellParent = (type, message) => window.parent.postMessage({type, ...(message ? {message} : {})}, origin);
  function ownController() {
    return new Promise((resolve, reject) => {
      const container = navigator.serviceWorker;
      const cleanup = () => { clearTimeout(timer); container.removeEventListener('controllerchange', check); };
      const check = () => {
        const worker = container.controller;
        if (worker?.scriptURL === workerURL) { cleanup(); resolve(worker); }
      };
      const timer = setTimeout(() => { cleanup(); reject(new Error('请刷新复盘入口后重新解锁。')); }, 15000);
      container.addEventListener('controllerchange', check);check();
    });
  }
  const rpc = async (type, fields = {}) => {
    const worker = await ownController();
    // A lock can arrive while this new document is waiting to be controlled.
    // Never install a captured key after that authority has been forgotten.
    if (type === 'REPLAY_INSTALL_SESSION' && (locked || !key || fields.key !== key || fields.issuedAt !== issuedAt)) {
      throw new Error('访问会话已结束。');
    }
    return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => { channel.port1.close(); reject(new Error('解锁连接超时，请重新输入口令。')); }, 10000);
    channel.port1.onmessage = event => {
      clearTimeout(timer); channel.port1.close();
      if (event.data?.ok) resolve(event.data);
      else reject(new Error(event.data?.error || '无法解锁复盘。'));
    };
    worker.postMessage({type, ...fields}, [channel.port2]);
    });
  };
  function forget() {
    locked = true; key = null; manifest = null; release = null; issuedAt = 0;
    clearTimeout(expiryTimer);
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
        await rpc('REPLAY_INSTALL_SESSION', {key, manifest, release, issuedAt});
        if (!locked) { tellParent('REPLAY_UNLOCKED'); return true; }
        return false;
      } catch (error) {
        if (!locked) { forget(); tellParent('REPLAY_ERROR', error.message); }
        return false;
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
        tellParent('REPLAY_ERROR', '口令会话无效，请重新解锁。'); return;
      }
      key = incoming.key; manifest = incoming.manifest; release = incoming.release;
      issuedAt = Number.isSafeInteger(incoming.issuedAt) ? incoming.issuedAt : Date.now(); locked = false;
      expiryTimer = setTimeout(() => lock(), Math.max(0, issuedAt + 12 * 60 * 60 * 1000 - Date.now()));
      install().then(ok=>{
        if(ok && incoming.html)render(incoming.html).catch(()=>{if(!locked)tellParent('REPLAY_RESOURCE_ERROR');});
      });
    } else if (event.data?.type === 'REPLAY_LOCK') lock();
  });
  navigator.serviceWorker.addEventListener('message', event => {
    // WebKit may expose different wrappers for the same worker. Never send a
    // key to event.source: RPC always targets this document's verified controller.
    if (event.source?.scriptURL !== workerURL || navigator.serviceWorker.controller?.scriptURL !== workerURL) return;
    if (event.data?.type === 'REPLAY_NEED_KEY') install();
    else if (event.data?.type === 'REPLAY_SESSION_EXPIRED') { forget(); tellParent('REPLAY_LOCKED'); }
    else if (event.data?.type === 'REPLAY_RESOURCE_ERROR') tellParent('REPLAY_RESOURCE_ERROR');
    else if (event.data?.type === 'REPLAY_CONTENT_ERROR') tellParent('REPLAY_ERROR', '复盘文件校验失败，请刷新后重试。');
  });
  navigator.serviceWorker.addEventListener('controllerchange', () => { if (key && !locked) install(); });
  window.addEventListener('pagehide', () => { forget(); navigator.serviceWorker.controller?.postMessage({type: 'REPLAY_REVOKE_SESSION'}); });
  tellParent('REPLAY_BRIDGE_READY');
})();
