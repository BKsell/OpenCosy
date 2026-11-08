'use strict';

// webworkerfileorigin.js —— Web Worker / SharedWorker 来源校验。
//
// Worker 脚本如果来自任意 file: 或 data: 源，就能绕开页面 CSP 读本地文件。
// 这里给 main 进程一道纯函数：判断 new Worker(url) 该不该放行。

// shouldAllowWorkerOrigin 入参：
//   pageUrl      调用 Worker 的页面 URL
//   workerUrl    传给 new Worker() 的 URL
//   allowDataUrlForTrustedPage 是否允许页面用 data: Worker（高风险，默认 false）
// 返回 { allow, reason }
function shouldAllowWorkerOrigin(opts) {
  const o = opts || {};
  const page = safeUrl(o.pageUrl);
  const worker = safeUrl(o.workerUrl);
  if (!page || !worker) {
    return { allow: false, reason: 'bad-url' };
  }
  if (page.protocol === 'file:') {
    return { allow: false, reason: 'file-page-disallowed' };
  }
  if (worker.protocol === 'data:') {
    if (!o.allowDataUrlForTrustedPage) {
      return { allow: false, reason: 'data-worker-disallowed' };
    }
  }
  if (worker.protocol === 'blob:') {
    // blob: Worker 必须和页面同源。
    if (worker.origin !== page.origin) {
      return { allow: false, reason: 'blob-cross-origin' };
    }
  }
  if (worker.protocol === 'http:' || worker.protocol === 'https:') {
    if (worker.origin !== page.origin) {
      return { allow: false, reason: 'cross-origin-worker' };
    }
  }
  return { allow: true, reason: 'ok' };
}

function safeUrl(u) {
  try {
    return new URL(String(u || ''));
  } catch {
    return null;
  }
}

module.exports = {
  shouldAllowWorkerOrigin,
};
