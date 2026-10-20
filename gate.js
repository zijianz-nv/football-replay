(() => {
  'use strict';
  const base = new URL('./', location.href), format = 'football-sealed-v1';
  const form = document.querySelector('#unlock-form'), input = document.querySelector('#password');
  const message = document.querySelector('#gate-message'), button = document.querySelector('#unlock');
  const gate = document.querySelector('#gate'), viewer = document.querySelector('#viewer');
  const loadNotice = document.querySelector('#load-notice');
  let active = null, iframe = null, attempt = 0;
  let restoreTimer = null, entryTimer = null, viewReady = false;
  let startupFailed = false, startupStep = 0, noticeKind = null;
  const shellVersion = '20261020-mobile6';
  const scriptLabels = {
    'data.js':'比赛数据', 'ball-visibility.js':'球的位置',
    'person-continuity.js':'球员轨迹', 'team-statistics.js':'技术统计',
    'player-details.js':'球员资料', 'app.js':'复盘界面', 'mobile-layout.js':'手机布局'
  };
  const closingFrames = new Map();
  const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const aad = text => new TextEncoder().encode(text);
  const note = (text, busy = false) => { message.textContent = text; message.classList.toggle('busy', busy); };
  const failure = code => Object.assign(new Error(code), {code});
  const errorText = code => ({
    unsupported:'当前浏览器缺少解锁所需功能，请更新浏览器后重试。（S01）',
    worker:'浏览器的解锁服务未能启动，请刷新页面重试。（S02）',
    config:'入口配置加载失败，请检查网络后重试。（N01）',
    manifest:'加密目录加载失败，请检查网络后重试。（N02）',
    entry:'复盘首页加载失败，请检查网络后重试。（N03）',
    integrity:'复盘文件校验失败，请刷新页面重试。（D01）',
    SESSION_INVALID:'解锁会话校验失败，请重新输入口令。（S04）',
    CONTENT_INVALID:'复盘文件校验失败，请刷新页面重试。（D01）'
  }[code] || '内容暂时无法载入，请刷新页面重试。（U01）');
  function showLoadNotice(text, kind = 'progress') {
    noticeKind=kind;
    if (!loadNotice) return;
    loadNotice.querySelector('span').textContent = text;
    loadNotice.hidden = false;
  }
  const phaseText = code => ({
    controller:'正在连接解锁服务…（M6-C）',
    received:'解锁请求已收到，正在建立会话…（M6-I）',
    client_lookup:'正在确认当前页面…（M6-L）',
    key_import:'正在处理兼容连接…（M6-K）',
    installed:'连接已建立，正在准备比赛数据…（M6-R）',
    status_check:'正在核验连接状态…（M6-P）',
    byte_retry:'正在尝试兼容连接…（M6-B）',
    render:'连接已建立，正在准备比赛数据…（M6-R）'
  }[code] || '正在打开复盘…');
  function hideLoadNotice() {
    noticeKind=null;
    if(loadNotice)loadNotice.hidden=true;
  }
  function watchStartup(text, delay = 45000) {
    clearTimeout(entryTimer);
    const frame=iframe;
    entryTimer=setTimeout(()=>{
      entryTimer=null;
      if(iframe===frame && !viewReady && !startupFailed && noticeKind!=='error')showLoadNotice(text);
    },delay);
  }
  async function fetchBytes(path, code, limit) {
    // Retry transport failures only. A failed authentication is never retried as a network error.
    for (let trial=0;trial<3;trial++) {
      const controller=new AbortController();let timer,reader;
      const progress=()=>{clearTimeout(timer);timer=setTimeout(()=>controller.abort(),30000);};
      try {
        progress();
        const response=await fetch(localURL(path),{cache:'no-store',signal:controller.signal});
        if(!response.ok)throw failure(code);
        reader=response.body.getReader();
        const parts=[];let size=0;
        for(;;) {
          const {value,done}=await reader.read();
          if(done)break;
          size+=value.byteLength;if(size>limit)throw failure('integrity');
          parts.push(value);progress();
        }
        const result=new Uint8Array(size);let offset=0;
        for(const part of parts){result.set(part,offset);offset+=part.byteLength;}
        return result;
      } catch(error) {
        if(error.code==='integrity')throw error;
        if(trial===2)throw failure(code);
        await new Promise(resolve=>setTimeout(resolve,350*(trial+1)));
      } finally {clearTimeout(timer);controller.abort();reader?.releaseLock();}
    }
  }
  function localURL(path) {
    const url = new URL(path, base);
    if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname)) throw new Error('Invalid asset');
    return url;
  }
  async function serviceWorker() {
    if (!isSecureContext || !navigator.serviceWorker || !crypto.subtle || !window.DecompressionStream) throw new Error('unsupported');
    // A versioned script URL makes us wait for the worker that understands this
    // release, rather than mistaking a previous active worker for the new one.
    const workerURL = localURL(`gate-sw.js?v=${shellVersion}`).href;
    let registerTimer;
    const registration = await Promise.race([
      navigator.serviceWorker.register(workerURL, {scope:base.pathname, updateViaCache:'none'}),
      new Promise((_,reject)=>{registerTimer=setTimeout(()=>reject(failure('worker')),30000);})
    ]).finally(()=>clearTimeout(registerTimer));
    if (registration.scope !== base.href) throw new Error('worker');
    await new Promise((resolve,reject) => {
      const cleanup=()=>{clearTimeout(timeout);navigator.serviceWorker.removeEventListener('controllerchange',check);};
      const check=()=>{if(navigator.serviceWorker.controller?.scriptURL===workerURL){cleanup();resolve();}};
      const timeout=setTimeout(()=>{cleanup();reject(failure('worker'));},30000);
      navigator.serviceWorker.addEventListener('controllerchange',check);check();
    });
  }
  async function decryptIndex(key, manifest) {
    const file=manifest.files['index.html'];
    if (!file || file.size > 1024*1024 || file.chunks.length > 4) throw new Error('Invalid entry');
    const parts=[];
    for (let i=0;i<file.chunks.length;i++) {
      const c=file.chunks[i],cipher=await fetchBytes(c.url,'entry',2*1024*1024);
      try {parts.push(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(c.iv),additionalData:aad(`${format}\n${manifest.release}\nindex.html\n${i}`)},key,cipher));}
      catch {throw failure('integrity');}
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
  function retireFrame() {
    viewReady=false;startupFailed=false;startupStep=0;noticeKind=null;
    clearInterval(restoreTimer);restoreTimer=null;
    clearTimeout(entryTimer);entryTimer=null;
    const closing=iframe;iframe=null;
    if(closing) {
      // Pause immediately; revocation and removal below cancel pending media.
      // Reloading a now-empty media URL can reject a pending WebKit play request.
      for(const video of closing.contentDocument?.querySelectorAll('video')||[]) {
        video.pause();
      }
      closingFrames.set(closing,setTimeout(()=>closeFrame(closing),500));
      closing.contentWindow?.postMessage({type:'REPLAY_LOCK'},location.origin);
    }
  }
  function mountFrame(restore = null) {
    if(!active)return;
    retireFrame();
    const frame=document.createElement('iframe');iframe=frame;
    frame.title='完整比赛复盘';frame.allow='fullscreen';frame.referrerPolicy='no-referrer';
    // A real document URL gives WebKit its own native service-worker client.
    // srcdoc can incorrectly send its install message using the parent's client ID.
    frame.src=localURL(`gate-frame.html?v=${shellVersion}`).href;
    document.querySelector('#frame-host').append(frame);
    gate.hidden=true;viewer.hidden=false;button.disabled=false;
    showLoadNotice(phaseText('controller'));
    watchStartup('复盘仍在加载，可点击重试，无需重复输入口令。（S03-W）',35000);
    if(restore && Number.isFinite(restore.time)) {
      const deadline=Date.now()+120000;
      restoreTimer=setInterval(()=>{
        if(iframe!==frame || Date.now()>deadline){clearInterval(restoreTimer);restoreTimer=null;return;}
        const app=frame.contentWindow?.matchReview,video=frame.contentDocument?.querySelector('video');
        if(!app?.getState().mediaReady || !video)return;
        clearInterval(restoreTimer);restoreTimer=null;
        app.seekTo(restore.time);
        video.playbackRate=restore.rate;video.muted=restore.muted;video.volume=restore.volume;
        if(!restore.paused)video.play().catch(()=>{});
      },200);
    }
  }
  function lock(text='已退出复盘。') {
    attempt++;retireFrame();active=null;
    hideLoadNotice();
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
      if(event.data.version!==shellVersion){
        clearTimeout(entryTimer);entryTimer=null;
        startupFailed=true;
        showLoadNotice('页面版本未更新，请刷新后重新打开。（S05）','error');return;
      }
      iframe.contentWindow.postMessage({type:'REPLAY_UNLOCK',key:active.key,keyEnvelope:active.keyEnvelope,manifest:active.manifest,
        release:active.manifest.release,issuedAt:active.issuedAt,html:active.html},location.origin);
    } else if(event.data?.type==='REPLAY_LOCKED') lock('访问已结束，请重新输入口令。');
    else if(event.data?.type==='REPLAY_VIEW_READY') {
      if(startupFailed)return;
      viewReady=true;clearTimeout(entryTimer);entryTimer=null;
      if(noticeKind!=='error')hideLoadNotice();
    }
    else if(event.data?.type==='REPLAY_UNLOCKED') {
      if(startupFailed)return;
      // Reconnecting an already-rendered view does not require a second render.
      if(viewReady){
        clearTimeout(entryTimer);entryTimer=null;
        if(noticeKind!=='error')hideLoadNotice();
      } else if(!startupStep && noticeKind!=='error') {
        showLoadNotice(phaseText('render'));
        watchStartup('连接已建立，但复盘尚未启动，可重试加载，无需重复输入口令。（N05）',30000);
      }
    }
    else if(event.data?.type==='REPLAY_LOAD_PROGRESS') {
      if(viewReady || startupFailed)return;
      const {index,total,resource,stage,received,totalBytes}=event.data;
      if(!Object.hasOwn(scriptLabels,resource) || !Number.isSafeInteger(index) ||
          !Number.isSafeInteger(total) || index<1 || total>32 || index>total ||
          index<startupStep || !['fetch','execute','complete'].includes(stage) ||
          !Number.isSafeInteger(totalBytes) || totalBytes<=0 || totalBytes>32*1024*1024 ||
          !Number.isSafeInteger(received) || received<0 || received>totalBytes)return;
      startupStep=index;
      const label=scriptLabels[resource];
      const action=stage==='fetch'?'正在读取':stage==='execute'?'正在初始化':'已准备';
      const percent=stage==='fetch' && received?` ${Math.floor(received/totalBytes*100)}%`:'';
      showLoadNotice(`${action}${label}${percent}（${index}/${total}）…`);
      watchStartup(`${label}仍在加载，可点击重试，无需重复输入口令。（M6-W${index}）`);
    }
    else if(event.data?.type==='REPLAY_STARTUP_ERROR') {
      if(viewReady || startupFailed)return;
      startupFailed=true;clearTimeout(entryTimer);entryTimer=null;
      const {code,resource,index}=event.data;
      const label=Object.hasOwn(scriptLabels,resource)?scriptLabels[resource]:'复盘内容';
      const reason=({LOAD_TIMEOUT:'读取超时',LOAD_FAILED:'读取失败',
        SCRIPT_EXECUTION:'启动失败',APP_INIT_FAILED:'未能完成初始化'})[code]||'加载失败';
      const suffix=({LOAD_TIMEOUT:'T',LOAD_FAILED:'F',SCRIPT_EXECUTION:'J',APP_INIT_FAILED:'I'})[code]||'F';
      const step=Number.isSafeInteger(index)&&index>=0&&index<=32?index:0;
      showLoadNotice(`${label}${reason}，点击重试加载，无需重复输入口令。（M6-${suffix}${step}）`,'error');
    }
    else if(event.data?.type==='REPLAY_PHASE') {
      if(!viewReady && !startupFailed && !startupStep && noticeKind!=='error')showLoadNotice(phaseText(event.data.code));
    }
    else if(event.data?.type==='REPLAY_RESOURCE_ERROR') {
      // Startup reads own their bounded retries and precise failure messages.
      if(viewReady)showLoadNotice('部分内容加载失败，可重试并回到当前播放位置。（N04）','error');
    }
    else if(event.data?.type==='REPLAY_RECONNECTING') {
      if(startupFailed || noticeKind==='error' || (!viewReady && startupStep))return;
      clearTimeout(entryTimer);entryTimer=null;
      showLoadNotice(phaseText(event.data.code==='KEY_TRANSFER_FAILED' || event.data.code==='SESSION_TIMEOUT'?'byte_retry':'controller'),'reconnecting');
    }
    else if(event.data?.type==='REPLAY_RETRYABLE_ERROR') {
      if(startupFailed)return;
      clearTimeout(entryTimer);entryTimer=null;
      if(!viewReady)startupFailed=true;
      const code=({SESSION_TIMEOUT:'S03-A',KEY_TRANSFER_FAILED:'S03-K',CLIENT_LOOKUP_TIMEOUT:'S03-L',CLIENT_UNAVAILABLE:'S03-L'})[event.data.code]||'S03-C';
      showLoadNotice(`解锁连接暂时中断，点击重试加载，无需重复输入口令。（${code}）`,'error');
    }
    else if(event.data?.type==='REPLAY_ERROR') lock(errorText(event.data.code));
  });
  form.addEventListener('submit',async event=>{
    event.preventDefault();const current=++attempt;button.disabled=true;note('正在验证口令…',true);
    let stage='worker';
    try {
      await serviceWorker();
      if(current!==attempt)return;
      stage='config';
      const config=JSON.parse(new TextDecoder().decode(await fetchBytes('sealed.json','config',64*1024)));
      if(config.format!==format || config.kdf.hash!=='SHA-256' || config.kdf.iterations<600000 || config.kdf.iterations>2000000)throw new Error('config');
      const material=await crypto.subtle.importKey('raw',aad(input.value),{name:'PBKDF2'},false,['deriveKey']);
      const kek=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(config.kdf.salt),iterations:config.kdf.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
      stage='manifest';
      const manifestCipher=await fetchBytes(config.manifest.url,'manifest',4*1024*1024);
      let plain;
      try {plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(config.manifest.iv),additionalData:aad(`${format}\n${config.release}\nmanifest`)},kek,manifestCipher);}
      catch {throw new Error('password');}
      let manifest;
      try {manifest=JSON.parse(new TextDecoder().decode(plain));}
      finally {new Uint8Array(plain).fill(0);plain=null;}
      if(manifest.format!==format || manifest.release!==config.release || !manifest.files)throw new Error('config');
      const raw=bytes(manifest.dataKey);let key,keyEnvelope;
      try {
        if(raw.length!==32)throw new Error('config');
        key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']);
        // Keep a small encrypted memory-only envelope for workers that cannot
        // deserialize CryptoKey. The temporary bytes are transferred, never sent by fetch.
        const envelopeKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
        const iv=crypto.getRandomValues(new Uint8Array(12));
        const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv,
          additionalData:aad(`${format}\n${manifest.release}\nsession-key`)},envelopeKey,raw);
        keyEnvelope={key:envelopeKey,iv,cipher};
      }
      finally {raw.fill(0);delete manifest.dataKey;}
      input.value='';
      note('正在打开复盘…',true);
      stage='entry';
      const html=await decryptIndex(key,manifest);if(current!==attempt)return;
      const documentCopy=new DOMParser().parseFromString(html,'text/html');
      if(documentCopy.querySelector('base'))throw new Error('config');
      const baseTag=documentCopy.createElement('base');baseTag.href=localURL('view/').href;
      documentCopy.head.prepend(baseTag);
      const badge=documentCopy.querySelector('.local-badge');if(badge)badge.textContent='比赛复盘';
      active={key,keyEnvelope,manifest,issuedAt:Date.now(),html:'<!doctype html>\n'+documentCopy.documentElement.outerHTML};
      mountFrame();
    } catch(error) {
      if(current!==attempt)return;active=null;button.disabled=false;
      note(error.message==='password'?'口令不正确，请重试。':errorText(error.code||(error.message==='unsupported'?'unsupported':stage)));
    }
  });
  document.querySelector('#lock').addEventListener('click',()=>lock());
  document.querySelector('#retry-content')?.addEventListener('click',()=>{
    if(!active || !iframe)return;
    const app=iframe.contentWindow?.matchReview,video=iframe.contentDocument?.querySelector('video');
    const restore=app&&video?{time:app.getState().sourceTime,paused:video.paused,
      rate:video.playbackRate,muted:video.muted,volume:video.volume}:null;
    mountFrame(restore);
  });
  document.querySelector('#dismiss-content')?.addEventListener('click',()=>{loadNotice.hidden=true;});
  document.querySelector('#show-password').addEventListener('click',event=>{
    const show=input.type==='password';input.type=show?'text':'password';event.currentTarget.textContent=show?'隐藏':'显示';event.currentTarget.setAttribute('aria-pressed',String(show));
  });
  window.addEventListener('pagehide',()=>{
    attempt++;button.disabled=false;active=null;clearInterval(restoreTimer);restoreTimer=null;clearTimeout(entryTimer);entryTimer=null;
    if(iframe){iframe.contentWindow?.postMessage({type:'REPLAY_LOCK'},location.origin);iframe.remove();iframe=null;}
    for(const frame of closingFrames.keys())closeFrame(frame);
    input.value='';viewer.hidden=true;gate.hidden=false;
  });
})();
