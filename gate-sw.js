/* Encrypted replay transport. No plaintext or key is written to persistent storage. */
'use strict';
const FORMAT = 'football-sealed-v1';
const SCOPE = new URL(self.registration.scope);
const VIEW_PREFIX = `${SCOPE.pathname}view/`;
const SESSION_MS = 12 * 60 * 60 * 1000;
const MAX_CHUNK_BYTES = 8 * 1024 * 1024;
const sessions = new Map();
const waiting = new Map();
const pendingInstalls = new Set();
let lastCleanup = 0;
const encoder = new TextEncoder();

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

function cleanPath(path) {
  if (typeof path !== 'string' || !path || path.length > 500 || /[\\%\x00-\x1f\x7f]/.test(path)) return null;
  const parts = path.split('/');
  if (parts.some(part => !part || part === '.' || part === '..' || part.startsWith('.'))) return null;
  return path;
}
function integer(value) { return Number.isSafeInteger(value) && value >= 0; }
function decode64(value, size) {
  if (typeof value !== 'string' || value.length > 100) throw new Error('Invalid nonce');
  const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0));
  if (bytes.length !== size) throw new Error('Invalid nonce');
  return bytes;
}
function validateManifest(manifest, release) {
  if (!manifest || manifest.format !== FORMAT || manifest.release !== release ||
      typeof release !== 'string' || !/^[A-Za-z0-9_-]{8,100}$/.test(release) ||
      !manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files)) throw new Error('Invalid manifest');
  const entries = Object.entries(manifest.files);
  if (!entries.length || entries.length > 1024) throw new Error('Invalid file count');
  const files = new Map();
  for (const [path, file] of entries) {
    if (!cleanPath(path) || !file || !integer(file.size) || !integer(file.encodedSize) ||
        file.size > 4 * 1024 ** 3 || file.encodedSize > 4 * 1024 ** 3 ||
        !['gzip', 'identity'].includes(file.encoding) ||
        typeof file.mime !== 'string' || !/^[a-z0-9.+-]+\/[a-z0-9.+-]+(?:; charset=utf-8)?$/i.test(file.mime) ||
        !Array.isArray(file.chunks) || file.chunks.length > 4096) throw new Error('Invalid file');
    if (file.encoding === 'identity' && file.encodedSize !== file.size) throw new Error('Invalid size');
    let offset = 0;
    const chunks = file.chunks.map(chunk => {
      if (!chunk || typeof chunk.url !== 'string' || !/^payload\/[A-Za-z0-9_-]+\.bin$/.test(chunk.url) ||
          chunk.offset !== offset || !integer(chunk.length) || chunk.length < 1 || chunk.length > MAX_CHUNK_BYTES) throw new Error('Invalid chunk');
      const encoding = chunk.encoding ?? 'identity';
      const encodedLength = chunk.encodedLength ?? chunk.length;
      if (!['identity', 'gzip'].includes(encoding) || !integer(encodedLength) ||
          encodedLength < 1 || encodedLength > MAX_CHUNK_BYTES ||
          (encoding === 'identity' && encodedLength !== chunk.length) ||
          (encoding === 'gzip' && file.encoding !== 'identity')) throw new Error('Invalid chunk encoding');
      offset += chunk.length;
      return {url: new URL(chunk.url, SCOPE).href, iv: decode64(chunk.iv, 12), offset: chunk.offset,
        length: chunk.length, encoding, encodedLength};
    });
    if (offset !== file.encodedSize) throw new Error('Incomplete file');
    files.set(path, {mime: file.mime, size: file.size, encodedSize: file.encodedSize, encoding: file.encoding, chunks});
  }
  return files;
}
function validKey(key) {
  return key && key.type === 'secret' && key.extractable === false &&
    key.algorithm?.name === 'AES-GCM' && key.algorithm.length === 256 && key.usages?.includes('decrypt');
}
function isLive(session) {
  return session && !session.revoked && session.key && Date.now() < session.expiresAt;
}
function resolveWaiters(clientId, session) {
  const pending = waiting.get(clientId);
  if (!pending) return;
  waiting.delete(clientId);
  for (const resolve of pending) resolve(session);
}
function revoke(clientId, reason = 'locked') {
  const session = sessions.get(clientId);
  if (session) {
    session.revoked = true;
    session.key = null;
    session.files.clear();
    for (const controller of session.aborters) controller.abort();
    session.aborters.clear();
    sessions.delete(clientId);
  }
  resolveWaiters(clientId, null);
  if (reason === 'expired') self.clients.get(clientId).then(client => client?.postMessage({type: 'REPLAY_SESSION_EXPIRED'}));
}
async function cleanup() {
  if (Date.now() - lastCleanup < 60000) return;
  lastCleanup = Date.now();
  for (const [id, session] of sessions) {
    if (Date.now() >= session.expiresAt) revoke(id, 'expired');
    else if (!await self.clients.get(id)) revoke(id);
  }
}

self.addEventListener('message', event => {
  const clientId = event.source?.id;
  const data = event.data;
  if (!clientId || !data || typeof data.type !== 'string') return;
  // Invalidate older asynchronous installs immediately when a lock arrives.
  // Otherwise an install waiting in clients.get() could recreate a revoked session.
  if(data.type==='REPLAY_REVOKE_SESSION'){
    for(const pending of pendingInstalls)if(pending.clientId===clientId)pending.cancelled=true;
    revoke(clientId);
  }
  const operation = data.type==='REPLAY_INSTALL_SESSION' ? {clientId,cancelled:false} : null;
  if(operation)pendingInstalls.add(operation);
  const reply = result => {
    // Both acknowledgements refer only to this message's native client.
    // No key, manifest or session authority is carried in either reply.
    try {event.ports?.[0]?.postMessage(result);} catch (_) {}
    if(typeof data.requestId==='string' && /^[0-9a-f]{32}$/.test(data.requestId)){
      try {event.source.postMessage({type:'REPLAY_SESSION_REPLY',requestId:data.requestId,result});} catch (_) {}
    }
  };
  event.waitUntil((async () => {
    try {
      await cleanup();
      if (data.type === 'REPLAY_REVOKE_SESSION') {
        reply({ok: true});
      } else if (data.type === 'REPLAY_INSTALL_SESSION') {
        if (!await self.clients.get(clientId) || !validKey(data.key) ||
            !integer(data.issuedAt) || data.issuedAt > Date.now() + 5000 || Date.now() - data.issuedAt >= SESSION_MS) throw new Error('Invalid session');
        if(operation.cancelled)throw new Error('Session revoked during installation');
        const existing = sessions.get(clientId);
        // Concurrent cold-start resources can each request a key before the first reply arrives.
        // Re-installing the same client generation must not abort that client's active streams.
        if (isLive(existing) && existing.release === data.release && existing.issuedAt === data.issuedAt) {
          resolveWaiters(clientId, existing);
          reply({ok: true, expiresAt: existing.expiresAt});
          return;
        }
        const files = validateManifest(data.manifest, data.release);
        if (!sessions.has(clientId) && sessions.size >= 128) throw new Error('Too many open views');
        if (sessions.has(clientId)) revoke(clientId);
        const session = {key: data.key, files, release: data.release, issuedAt: data.issuedAt, expiresAt: data.issuedAt + SESSION_MS,
          revoked: false, aborters: new Set()};
        sessions.set(clientId, session);
        resolveWaiters(clientId, session);
        reply({ok: true, expiresAt: session.expiresAt});
      }
    } catch (_) {
      reply({ok: false, error: '无法建立解锁会话，请重新输入口令。'});
    } finally {
      if(operation)pendingInstalls.delete(operation);
    }
  })());
});

async function sessionFor(clientId) {
  if (!clientId) return null; // Navigations and copied URLs never inherit an unlocked frame.
  const current = sessions.get(clientId);
  if (isLive(current)) return current;
  if (current) { revoke(clientId, 'expired'); return null; }
  const client = await self.clients.get(clientId);
  if (!client) return null;
  return new Promise(resolve => {
    let completed = false;
    const finish = session => {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      waiting.get(clientId)?.delete(finish);
      if (waiting.get(clientId)?.size === 0) waiting.delete(clientId);
      resolve(session);
    };
    const timer = setTimeout(() => finish(null), 8000);
    if (!waiting.has(clientId)) waiting.set(clientId, new Set());
    waiting.get(clientId).add(finish);
    // Only this requesting client receives the challenge. No tab-wide/global unlock exists.
    client.postMessage({type: 'REPLAY_NEED_KEY'});
    const installed = sessions.get(clientId);
    if (isLive(installed)) finish(installed);
  });
}
function headers(type = 'text/plain; charset=utf-8') {
  return new Headers({'Content-Type': type, 'Cache-Control': 'private, no-store, max-age=0',
    'Pragma': 'no-cache', 'Expires': '0', 'X-Content-Type-Options': 'nosniff',
    'Cross-Origin-Resource-Policy': 'same-origin', 'Referrer-Policy': 'no-referrer'});
}
function errorResponse(status, text, extra = {}) {
  const result = headers();
  for (const [name, value] of Object.entries(extra)) result.set(name, value);
  return new Response(text, {status, headers: result});
}
function parseRange(value, size) {
  const match = /^bytes=(\d*)-(\d*)$/i.exec(value.trim());
  if (!match || (!match[1] && !match[2]) || !size) return null;
  let start, end;
  if (!match[1]) {
    const suffix = Number(match[2]);
    if (!integer(suffix) || suffix === 0) return null;
    start = Math.max(0, size - suffix); end = size - 1;
  } else {
    start = Number(match[1]); end = match[2] ? Number(match[2]) : size - 1;
    if (!integer(start) || !integer(end) || start >= size || end < start) return null;
    end = Math.min(end, size - 1);
  }
  return {start, end};
}
function resourceError() {
  const error = new Error('Encrypted resource unavailable');
  error.code = 'RESOURCE_UNAVAILABLE';
  return error;
}
async function readCipherOnce(url, expected, signal, retry) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  let timer, reader;
  const progress = () => {
    clearTimeout(timer);
    // A slow connection is allowed to keep making progress; only a stalled read times out.
    timer = setTimeout(abort, 30000);
  };
  if (signal.aborted) abort();
  signal.addEventListener('abort', abort, {once: true});
  try {
    progress();
    const response = await fetch(url, {credentials: 'omit', redirect: 'error',
      cache: retry ? 'reload' : 'default', signal: controller.signal});
    if (!response.ok || !response.body) throw resourceError();
    // Fetch exposes decoded bytes. Content-Length may describe the CDN's gzip
    // transport instead, so validate the actual bounded body and the GCM tag.
    reader = response.body.getReader();
    const bytes = new Uint8Array(expected);
    let offset = 0;
    while (true) {
      progress();
      const {done, value} = await reader.read();
      if (done) break;
      if (offset + value.byteLength > expected) throw resourceError();
      bytes.set(value, offset); offset += value.byteLength;
    }
    if (offset !== expected) throw resourceError();
    return bytes;
  } catch (_) {
    throw resourceError();
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', abort);
    if (reader) await reader.cancel().catch(() => {});
    controller.abort();
  }
}
function retryDelay(ms, signal) {
  return new Promise(resolve => {
    const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve(); };
    const timer = setTimeout(finish, ms);
    signal.addEventListener('abort', finish, {once: true});
    if (signal.aborted) finish();
  });
}
async function readCipher(url, expected, signal) {
  for (let attempt = 0; attempt < 3; attempt++) {
    if (signal.aborted) throw resourceError();
    try { return await readCipherOnce(url, expected, signal, attempt > 0); }
    catch (error) {
      if (signal.aborted || attempt === 2) throw error;
      await retryDelay(attempt ? 1200 : 400, signal);
    }
  }
}
async function decodeChunk(encoded, chunk, signal) {
  if (encoded.byteLength !== chunk.encodedLength) throw new Error('Invalid encoded chunk length');
  if (chunk.encoding === 'identity') return encoded;
  // Authentication happens before decompression. Never allocate or return an
  // unbounded inflated buffer; range offsets still address the original MP4.
  const reader = new Blob([encoded]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
  const plain = new Uint8Array(chunk.length);
  let offset = 0;
  try {
    for (;;) {
      if (signal.aborted) throw new Error('Session locked');
      const {value, done} = await reader.read();
      if (done) break;
      if (offset + value.byteLength > plain.length) throw new Error('Invalid decompressed chunk length');
      plain.set(value, offset); offset += value.byteLength;
    }
    if (offset !== plain.length) throw new Error('Incomplete decompressed chunk');
    return plain;
  } finally { await reader.cancel().catch(() => {}); }
}
function encryptedStream(session, clientId, path, file, start, end) {
  const aborter = new AbortController();
  session.aborters.add(aborter);
  let cancelled = false;
  let index = file.chunks.findIndex(chunk => chunk.offset + chunk.length > start);
  const finish = () => { session.aborters.delete(aborter); };
  return new ReadableStream({
    async pull(controller) {
      try {
        if (!isLive(session)) throw new Error('Session locked');
        if (index < 0 || index >= file.chunks.length || file.chunks[index].offset > end) {
          finish(); controller.close(); return;
        }
        const chunk = file.chunks[index];
        const cipher = await readCipher(chunk.url, chunk.encodedLength + 16, aborter.signal);
        const encoded = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: chunk.iv,
          additionalData: encoder.encode(`${FORMAT}\n${session.release}\n${path}\n${index}`), tagLength: 128}, session.key, cipher));
        if (!isLive(session) || aborter.signal.aborted) throw new Error('Session locked');
        const plain = await decodeChunk(encoded, chunk, aborter.signal);
        if (!isLive(session) || aborter.signal.aborted) throw new Error('Session locked');
        if (plain.byteLength !== chunk.length) throw new Error('Invalid decrypted length');
        const from = Math.max(0, start - chunk.offset);
        const to = Math.min(chunk.length, end - chunk.offset + 1);
        index++;
        controller.enqueue(plain.subarray(from, to));
      } catch (error) {
        const expectedCancellation = cancelled || aborter.signal.aborted || !isLive(session);
        finish(); aborter.abort();
        if (!cancelled) controller.error(new Error(expectedCancellation ? '访问会话已结束。' : '无法解密复盘文件，请刷新后重试。'));
        if (!expectedCancellation) self.clients.get(clientId).then(client => client?.postMessage({
          type: error.code === 'RESOURCE_UNAVAILABLE' ? 'REPLAY_RESOURCE_ERROR' : 'REPLAY_CONTENT_ERROR'
        }));
        else if (Date.now() >= session.expiresAt && sessions.get(clientId) === session) revoke(clientId, 'expired');
      }
    },
    cancel() { cancelled = true; aborter.abort(); finish(); }
  }, {highWaterMark: 0});
}
function verifiedSizeStream(size) {
  let count = 0;
  return new TransformStream({
    transform(chunk, controller) {
      count += chunk.byteLength;
      if (count > size) throw new Error('Invalid decompressed size');
      controller.enqueue(chunk);
    },
    flush() { if (count !== size) throw new Error('Incomplete decompressed file'); }
  });
}
async function protectedResponse(event, path) {
  await cleanup();
  const session = await sessionFor(event.clientId);
  if (!isLive(session)) return errorResponse(401, '请在复盘入口输入口令后访问。');
  if (!['GET', 'HEAD'].includes(event.request.method)) return errorResponse(405, '不支持此请求。', {Allow: 'GET, HEAD'});
  if (!cleanPath(path)) return errorResponse(404, '文件不存在。');
  const file = session.files.get(path);
  if (!file) return errorResponse(404, '文件不存在。');
  let range = null;
  const rangeHeader = event.request.headers.get('Range');
  if (rangeHeader && !event.request.headers.has('If-Range')) {
    range = file.encoding === 'identity' ? parseRange(rangeHeader, file.size) : null;
    if (!range) return errorResponse(416, '请求范围无效。', {'Content-Range': `bytes */${file.size}`});
  }
  const responseHeaders = headers(file.mime);
  responseHeaders.set('Accept-Ranges', file.encoding === 'identity' ? 'bytes' : 'none');
  responseHeaders.set('Content-Length', String(range ? range.end - range.start + 1 : file.size));
  if (range) responseHeaders.set('Content-Range', `bytes ${range.start}-${range.end}/${file.size}`);
  let body = null;
  if (event.request.method !== 'HEAD' && file.encodedSize) {
    body = encryptedStream(session, event.clientId, path, file, range?.start ?? 0, range?.end ?? file.encodedSize - 1);
    if (file.encoding === 'gzip') {
      if (typeof DecompressionStream !== 'function') return errorResponse(503, '此浏览器暂不支持解密复盘，请使用新版浏览器。');
      body = body.pipeThrough(new DecompressionStream('gzip')).pipeThrough(verifiedSizeStream(file.size));
    }
  }
  return new Response(body, {status: range ? 206 : 200, headers: responseHeaders});
}
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin !== SCOPE.origin || !url.pathname.startsWith(VIEW_PREFIX)) return;
  let path;
  try { path = decodeURIComponent(url.pathname.slice(VIEW_PREFIX.length)); }
  catch (_) { event.respondWith(errorResponse(404, '文件不存在。')); return; }
  event.respondWith(protectedResponse(event, path).catch(() => errorResponse(503, '复盘暂时无法加载，请重新解锁。')));
});
