'use strict';

let d = {};

function bindDeps(x) {
  d = x;
}

function installCertificateErrorHandler() {
d.app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  try {
    if (d.certExceptionAllowed(url, certificate)) {
      event.preventDefault();
      callback(true);
      return;
    }
    event.preventDefault();
    callback(false);

    const verdict = d.certGuard.classifyCertError({ url, error, certificate });
    if (!verdict.host) return;
    // 只为主框架导航弹拦截页；子资源（图片/脚本等）证书错误静默阻止即可。
    let isMainFrame = false;
    try {
      const cur = webContents.getURL ? webContents.getURL() : '';
      isMainFrame = !cur || d.certGuard.normalizeHost(cur) === verdict.host;
    } catch { isMainFrame = true; }
    if (!isMainFrame) return;

    const nonce = d.makeCertChallenge(verdict, webContents.id);
    d.sendToRenderer('cert-error-blocked', {
      nonce,
      url: String(url).slice(0, 2048),
      host: verdict.host,
      code: verdict.code,
      overridable: verdict.overridable,
      title: verdict.title,
      detail: verdict.detail,
      cert: verdict.cert,
      shortFingerprint: d.certGuard.shortFingerprint(verdict.cert ? verdict.cert.fingerprint : ''),
    });
  } catch {
    // 任何意外都 fail-closed，绝不因异常而默认放行。
    try { event.preventDefault(); } catch {}
    try { callback(false); } catch {}
  }
});

d.ipcMain.handle('approve-cert-exception', (event, payload = {}) => {
  const challenge = d.consumeCertChallenge(payload.nonce);
  if (!challenge) return { ok: false, error: '挑战已过期或无效，请重新访问' };
  const verdict2 = d.certGuard.errorInfo(challenge.code);
  if (!verdict2.overridable) return { ok: false, error: '该证书错误不可绕过' };
  const ok = d.addCertException(challenge.host, {
    fingerprint: challenge.fingerprint ? `sha256/${challenge.fingerprint}` : '',
    subjectName: '',
    issuerName: '',
  }, challenge.code);
  if (!ok) return { ok: false, error: '例外记录失败' };
  // 放行后重新加载对应标签；找不到则只记录、不导航。
  try {
    const target = d.webContents.fromId(challenge.webContentsId);
    if (target && !target.isDestroyed()) {
      setImmediate(() => { try { target.reload(); } catch {} });
    }
  } catch {}
  d.sendToRenderer('cert-exception-updated', d.getCertExceptionStats());
  return { ok: true };
});

d.ipcMain.handle('list-cert-exceptions', (event, payload = {}) => ({
  entries: d.listCertExceptionEntries(payload.limit),
  stats: d.getCertExceptionStats(),
}));

d.ipcMain.handle('remove-cert-exception', (event, payload = {}) => {
  d.removeCertException(payload.host, payload.fingerprint);
  d.sendToRenderer('cert-exception-updated', d.getCertExceptionStats());
  return { ok: true };
});

d.ipcMain.handle('clear-cert-exceptions', () => {
  d.clearCertExceptions();
  d.sendToRenderer('cert-exception-updated', d.getCertExceptionStats());
  return { ok: true };
});

d.ipcMain.handle('get-cert-exception-stats', () => d.getCertExceptionStats());
}

module.exports = { bindDeps, installCertificateErrorHandler };
