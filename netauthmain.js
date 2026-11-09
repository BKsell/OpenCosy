'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

function setupNetworkAuth() {
  d.loadClientCertChoices();

  // HTTP/代理身份认证。isProxy 时走 407 判定，否则按 401 主/子框架判定。
  d.app.on('login', (loginEvent, webContents, request, authInfo, callback) => {
    loginEvent.preventDefault();
    const info = authInfo || {};
    const isProxy = info.isProxy === true;
    const verdict = isProxy
      ? d.netAuthGuard.classifyProxyAuth({ url: request && request.url, authInfo: info })
      : d.netAuthGuard.classifyServerAuth({
          url: request && request.url,
          // Electron 41 在 response details 里给 resourceType；缺省时按子框架
          // fail-closed，不允许在无法确认顶层的情况下弹框（可能泄露凭据）。
          isMainFrame: request && request.resourceType === 'mainFrame',
          authInfo: info,
        });
    d.authStats.recordEvent({ decision: verdict.decision, reason: verdict.reason, scheme: verdict.scheme });

    if (verdict.decision !== 'prompt') {
      d.failAuthCallback(callback);
      d.recordSecurityEvent('auth-blocked', 'warn',
        `${isProxy ? '代理' : '服务器'}认证被拦截：${verdict.reason}（${verdict.scheme || '未知方案'}）`,
        isProxy ? (verdict.host || 'proxy') : verdict.key);
      return;
    }

    const gate = d.authLimiter.request(verdict.key, Date.now());
    if (!gate.allow) {
      d.authStats.recordRateLimited();
      d.failAuthCallback(callback);
      d.recordSecurityEvent('auth-rate-limited', 'warn',
        `认证弹框过频已临时冷却：${verdict.key}（${gate.reason}）`, verdict.key);
      return;
    }

    // 有界待处理队列：超过上限直接取消最旧的同类挑战，防止 401 风暴堆积。
    if (pendingAuthChallenges.size >= netAuthGuard.MAX_PENDING_PROMPTS) {
      const oldest = d.pendingAuthChallenges.keys().next().value;
      d.rejectAuthChallenge(oldest);
    }

    const nonce = d.netAuthNonce();
    const timer = setTimeout(() => {
      if (!d.pendingAuthChallenges.has(nonce)) return;
      d.pendingAuthChallenges.delete(nonce);
      d.failAuthCallback(callback);
    }, d.netAuthGuard.AUTH_PROMPT_TIMEOUT_MS);
    d.pendingAuthChallenges.set(nonce, { callback, timer, key: verdict.key, kind: 'login' });

    d.sendToRenderer('network-auth-required', {
      nonce,
      isProxy,
      host: verdict.host || '',
      key: verdict.key,
      scheme: verdict.scheme,
      schemeLabel: d.netAuthGuard.describeAuthScheme(verdict.scheme),
      realm: verdict.realm || '',
      origin: d.authEventOrigin(d.webContents),
    });
  });

  // TLS 客户端证书：默认不发送，除非用户为该主机明确记住过一张证书的指纹。
  d.session.defaultSession.on('select-client-certificate', (certEvent, webContents, url, certificateList, callback) => {
    certEvent.preventDefault();
    const hostname = d.urlResolve.safeHostname(url);
    const remembered = hostname ? d.clientCertStore.get(hostname) : null;
    const pick = d.netAuthGuard.chooseClientCertificate({
      certificateList,
      rememberedFingerprint: remembered ? remembered.fingerprint : '',
    });
    if (pick.index >= 0 && certificateList[pick.index]) {
      try { callback(certificateList[pick.index]); } catch { try { callback(); } catch {} }
      return;
    }
    d.authStats.recordCertSuppressed();
    d.recordSecurityEvent('client-cert-blocked', 'info',
      `未自动发送客户端证书：${hostname || '未知主机'}（${pick.reason}）`, url);

    if (pendingAuthChallenges.size >= netAuthGuard.MAX_PENDING_PROMPTS) {
      try { callback(); } catch {}
      return;
    }
    const nonce = d.netAuthNonce();
    const timer = setTimeout(() => {
      if (!d.pendingAuthChallenges.has(nonce)) return;
      d.pendingAuthChallenges.delete(nonce);
      try { callback(); } catch {}
    }, d.netAuthGuard.AUTH_PROMPT_TIMEOUT_MS);
    d.pendingAuthChallenges.set(nonce, { callback, timer, key: url, kind: 'cert', certificateList, hostname });
    d.sendToRenderer('client-cert-required', {
      nonce,
      host: hostname,
      origin: d.authEventOrigin(d.webContents),
      certificates: d.sanitizeCertPickList(certificateList),
    });
  });
}

module.exports = { setupNetworkAuth, bindDeps };
