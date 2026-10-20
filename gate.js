(() => {
  'use strict';
  const base = new URL('./', location.href), format = 'football-sealed-v1';
  const form = document.querySelector('#unlock-form'), input = document.querySelector('#password');
  const message = document.querySelector('#gate-message'), button = document.querySelector('#unlock');
  const gate = document.querySelector('#gate'), viewer = document.querySelector('#viewer');
  let active = null, iframe = null, attempt = 0;
  const closingFrames = new Map();
  const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const aad = text => new TextEncoder().encode(text);
  const note = (text, busy = false) => { message.textContent = text; message.classList.toggle('busy', busy); };
  function localURL(path) {
    const url = new URL(path, base);
    if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname)) throw new Error('Invalid asset');
    return url;
  }
  async function serviceWorker() {
    if (!isSecureContext || !navigator.serviceWorker || !crypto.subtle || !window.DecompressionStream) throw new Error('unsupported');
    const workerURL = localURL('gate-sw.js').href;
    const registration = await navigator.serviceWorker.register(workerURL, {scope:base.pathname, updateViaCache:'none'});
    if (registration.scope !== base.href) throw new Error('worker');
    await new Promise((resolve,reject) => {
      const cleanup=()=>{clearTimeout(timeout);navigator.serviceWorker.removeEventListener('controllerchange',check);};
      const check=()=>{if(navigator.serviceWorker.controller?.scriptURL===workerURL){cleanup();resolve();}};
      const timeout=setTimeout(()=>{cleanup();reject(new Error('worker'));},15000);
      navigator.serviceWorker.addEventListener('controllerchange',check);check();
    });
  }
  async function decryptIndex(key, manifest) {
    const file=manifest.files['index.html'];
    if (!file || file.size > 1024*1024 || file.chunks.length > 4) throw new Error('Invalid entry');
    const parts=[];
    for (let i=0;i<file.chunks.length;i++) {
      const c=file.chunks[i],response=await fetch(localURL(c.url),{cache:'no-store'});
      if(!response.ok) throw new Error('network');
      parts.push(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(c.iv),additionalData:aad(`${format}\n${manifest.release}\nindex.html\n${i}`)},key,await response.arrayBuffer()));
    }
    let body=new Blob(parts).stream();
    if(file.encoding==='gzip')body=body.pipeThrough(new DecompressionStream('gzip'));
    const plain=await new Response(body).arrayBuffer();
    if(plain.byteLength!==file.size)throw new Error('Invalid entry');
    return new TextDecoder('utf-8',{fatal:true}).decode(plain);
  }
  function closeFrame(frame) {
    const timer=closingFrames.get(frame);if(timer)clearTimeout(timer);
    closingFrames.delete(frame);frame.remove();
  }
  function lock(text='已退出复盘。') {
    attempt++;
    const closing=iframe;iframe=null;active=null;
    if(closing) {
      // Stop playback immediately, while giving the bridge time to revoke its native client session.
      for(const video of closing.contentDocument?.querySelectorAll('video')||[]) {
        video.pause();video.removeAttribute('src');video.load();
      }
      closingFrames.set(closing,setTimeout(()=>closeFrame(closing),500));
      closing.contentWindow?.postMessage({type:'REPLAY_LOCK'},location.origin);
    }
    input.value='';button.disabled=false;viewer.hidden=true;gate.hidden=false;note(text);input.focus();
  }
  window.addEventListener('message',event=>{
    if(event.origin!==location.origin)return;
    if(event.data?.type==='REPLAY_LOCKED') {
      for(const frame of closingFrames.keys()) {
        if(event.source===frame.contentWindow){closeFrame(frame);return;}
      }
    }
    if(!iframe || event.source!==iframe.contentWindow)return;
    if(event.data?.type==='REPLAY_BRIDGE_READY' && active) {
      iframe.contentWindow.postMessage({type:'REPLAY_UNLOCK',key:active.key,manifest:active.manifest,release:active.manifest.release},location.origin);
    } else if(event.data?.type==='REPLAY_LOCKED') lock('访问已结束，请重新输入口令。');
    else if(event.data?.type==='REPLAY_ERROR') lock('内容暂时无法载入，请重新解锁。');
  });
  form.addEventListener('submit',async event=>{
    event.preventDefault();const current=++attempt;button.disabled=true;note('正在验证口令…',true);
    try {
      await serviceWorker();
      const response=await fetch(localURL('sealed.json'),{cache:'no-store'});if(!response.ok)throw new Error('network');
      const config=await response.json();
      if(config.format!==format || config.kdf.hash!=='SHA-256' || config.kdf.iterations<600000 || config.kdf.iterations>2000000)throw new Error('config');
      const material=await crypto.subtle.importKey('raw',aad(input.value),{name:'PBKDF2'},false,['deriveKey']);
      const kek=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(config.kdf.salt),iterations:config.kdf.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
      const manifestResponse=await fetch(localURL(config.manifest.url),{cache:'no-store'});if(!manifestResponse.ok)throw new Error('network');
      let plain;
      try {plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(config.manifest.iv),additionalData:aad(`${format}\n${config.release}\nmanifest`)},kek,await manifestResponse.arrayBuffer());}
      catch {throw new Error('password');}
      let manifest;
      try {manifest=JSON.parse(new TextDecoder().decode(plain));}
      finally {new Uint8Array(plain).fill(0);plain=null;}
      if(manifest.format!==format || manifest.release!==config.release || !manifest.files)throw new Error('config');
      const raw=bytes(manifest.dataKey);let key;
      try {if(raw.length!==32)throw new Error('config');key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']);}
      finally {raw.fill(0);delete manifest.dataKey;}
      input.value='';
      note('正在打开复盘…',true);
      const html=await decryptIndex(key,manifest);if(current!==attempt)return;
      const documentCopy=new DOMParser().parseFromString(html,'text/html');
      if(documentCopy.querySelector('base'))throw new Error('config');
      const baseTag=documentCopy.createElement('base');baseTag.href=localURL('view/').href;
      const bridge=documentCopy.createElement('script');bridge.src=localURL('gate-bridge.js').href;
      documentCopy.head.prepend(baseTag,bridge);
      const badge=documentCopy.querySelector('.local-badge');if(badge)badge.textContent='比赛复盘';
      active={key,manifest};iframe=document.createElement('iframe');iframe.title='完整比赛复盘';iframe.allow='fullscreen';iframe.referrerPolicy='no-referrer';
      iframe.srcdoc='<!doctype html>\n'+documentCopy.documentElement.outerHTML;
      document.querySelector('#frame-host').append(iframe);gate.hidden=true;viewer.hidden=false;button.disabled=false;
    } catch(error) {
      if(current!==attempt)return;active=null;button.disabled=false;
      note(error.message==='password'?'口令不正确，请重试。':error.message==='unsupported'?'请使用较新版本的 Safari、Chrome 或 Edge 打开。':'内容暂时无法载入，请稍后重试。');
    }
  });
  document.querySelector('#lock').addEventListener('click',()=>lock());
  document.querySelector('#show-password').addEventListener('click',event=>{
    const show=input.type==='password';input.type=show?'text':'password';event.currentTarget.textContent=show?'隐藏':'显示';event.currentTarget.setAttribute('aria-pressed',String(show));
  });
  window.addEventListener('pagehide',()=>{
    attempt++;button.disabled=false;active=null;
    if(iframe){iframe.contentWindow?.postMessage({type:'REPLAY_LOCK'},location.origin);iframe.remove();iframe=null;}
    for(const frame of closingFrames.keys())closeFrame(frame);
    input.value='';viewer.hidden=true;gate.hidden=false;
  });
})();
