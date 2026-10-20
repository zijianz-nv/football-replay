/* Runs only inside the decrypted srcdoc iframe. Key remains in this document's memory. */
(() => {
  'use strict';
  const bridgeURL = new URL(document.currentScript.src);
  const origin = bridgeURL.origin;
  const workerURL = new URL('gate-sw.js', bridgeURL).href;
  if (window.parent === window) return;
  let key = null, manifest = null, release = null, issuedAt = 0;
  let installing = null, expiryTimer = null, locked = false;
  const tellParent = (type, message) => window.parent.postMessage({type, ...(message ? {message} : {})}, origin);
  const rpc = (type, fields = {}) => new Promise((resolve, reject) => {
    const worker = navigator.serviceWorker.controller;
    if (!worker || worker.scriptURL !== workerURL) { reject(new Error('请刷新复盘入口后重新解锁。')); return; }
    const channel = new MessageChannel();
    const timer = setTimeout(() => { channel.port1.close(); reject(new Error('解锁连接超时，请重新输入口令。')); }, 10000);
    channel.port1.onmessage = event => {
      clearTimeout(timer); channel.port1.close();
      if (event.data?.ok) resolve(event.data);
      else reject(new Error(event.data?.error || '无法解锁复盘。'));
    };
    worker.postMessage({type, ...fields}, [channel.port2]);
  });
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
    installing = rpc('REPLAY_INSTALL_SESSION', {key, manifest, release, issuedAt});
    try { await installing; if (!locked) tellParent('REPLAY_UNLOCKED'); }
    catch (error) { forget(); tellParent('REPLAY_ERROR', error.message); }
    finally { installing = null; }
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
      issuedAt = Date.now(); locked = false;
      expiryTimer = setTimeout(() => lock(), 12 * 60 * 60 * 1000);
      install();
    } else if (event.data?.type === 'REPLAY_LOCK') lock();
  });
  navigator.serviceWorker.addEventListener('message', event => {
    if (event.source !== navigator.serviceWorker.controller || event.source?.scriptURL !== workerURL) return;
    if (event.data?.type === 'REPLAY_NEED_KEY') install();
    else if (event.data?.type === 'REPLAY_SESSION_EXPIRED') { forget(); tellParent('REPLAY_LOCKED'); }
    else if (event.data?.type === 'REPLAY_CONTENT_ERROR') tellParent('REPLAY_ERROR', '复盘文件校验失败，请刷新后重试。');
  });
  navigator.serviceWorker.addEventListener('controllerchange', () => { if (key && !locked) install(); });
  window.addEventListener('pagehide', () => { forget(); navigator.serviceWorker.controller?.postMessage({type: 'REPLAY_REVOKE_SESSION'}); });
  tellParent('REPLAY_BRIDGE_READY');
})();
