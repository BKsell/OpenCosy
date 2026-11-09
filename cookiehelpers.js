function parseSetCookieEntry(rawLine) {
  const line = String(rawLine == null ? '' : rawLine).trim();
  if (!line) return null;

  const segments = line.split(';');
  const nameValue = (segments.shift() || '').trim();
  const eq = nameValue.indexOf('=');
  // 没有 '=' 或名字为空的 Set-Cookie 无法构成 Cookie，按无效处理。
  if (eq <= 0) return null;
  const name = nameValue.slice(0, eq).trim();
  if (!name) return null;

  const attrs = [];
  let secure = false;
  let sameSite = '';
  let domainSet = false;
  let pathSet = false;

  for (const seg of segments) {
    const rawAttr = seg.trim();
    if (!rawAttr) continue;
    attrs.push(rawAttr);
    const aeq = rawAttr.indexOf('=');
    const attrName = (aeq >= 0 ? rawAttr.slice(0, aeq) : rawAttr).trim().toLowerCase();
    const attrValue = aeq >= 0 ? rawAttr.slice(aeq + 1).trim() : '';
    if (attrName === 'secure') secure = true;
    else if (attrName === 'domain') domainSet = true;
    else if (attrName === 'path') pathSet = true;
    else if (attrName === 'samesite') {
      const v = attrValue.toLowerCase();
      if (v === 'strict' || v === 'lax' || v === 'none') sameSite = v;
      else if (v === '') sameSite = 'lax'; // “SameSite” 无值时按 Lax
      else sameSite = v; // 非法值保留，交给后续按 None/缺省逻辑处理
    }
  }

  return { name, nameValue, attrs, raw: line, secure, sameSite, domainSet, pathSet };
}

// 从 headers 里取出全部 Set-Cookie。Electron 回调里响应头键可能是
// 'Set-Cookie' 或 'set-cookie'，值为字符串或数组。
function extractSetCookieHeaders(headers) {
  if (!headers || typeof headers !== 'object') return [];
  const key = Object.prototype.hasOwnProperty.call(headers, 'set-cookie')
    ? 'set-cookie'
    : (Object.prototype.hasOwnProperty.call(headers, 'Set-Cookie') ? 'Set-Cookie' : '');
  if (!key) return [];
  const v = headers[key];
  if (Array.isArray(v)) return v.slice();
  if (typeof v === 'string') return [v];
  return [];
}

// registrableDomain 取主机的“主域”用于第一方/第三方比较：取最后两段。
// 对常见多级后缀（co.uk/com.cn）没有公共后缀表时会误判，因此这里只做
// “eTLD+1 近似”，跨站判定的权威信号仍交给 Chromium 的 isSameSite（通过
// details.siteForCookies / 同源比较），本函数仅用于聚合台账的展示归并。
const MULTI_PART_SUFFIX = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.jp', 'com.au', 'com.br', 'co.kr',
]);
function registrableDomain(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return h;
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIX.has(last2) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return last2;
}

// hostOf 从 URL 里安全取小写 hostname，失败返回 ''。
function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ''; }
}

// isThirdPartyContext 判定该响应是否处于跨站（第三方）Cookie 上下文。
// 优先使用 Chromium 在 details 里给出的 siteForCookies（形如 https://host），
// 与响应 URL 的可注册域比较；缺失时回退到 documentURL/originURL。
function isThirdPartyContext(details) {
  const respHost = hostOf(details && details.url);
  if (!respHost) return false;
  const candidates = [details && details.siteForCookies,
    details && details.documentURL, details && details.originURL]
    .filter(u => typeof u === 'string' && /^https?:/i.test(u));
  const respReg = registrableDomain(respHost);
  for (const c of candidates) {
    const ctxHost = hostOf(c);
    if (!ctxHost) continue;
    // about:blank / 顶层初始化时 documentURL 可能就是响应自身，视为第一方。
    if (registrableDomain(ctxHost) !== respReg) return true;
  }
  return false;
}

// cookiePrefixViolation 校验 __Host- / __Secure- 名前缀约束。
// 返回 null 表示合规；否则返回违规原因码。
//   __Host-  ：必须 Secure、Path=/、不得带 Domain；
//   __Secure-：必须 Secure。
function cookiePrefixViolation(entry, isSecureResponse) {
  const n = entry.name;
  if (n.startsWith('__Host-')) {
    if (!isSecureResponse || !entry.secure) return 'host-prefix-not-secure';
    if (entry.domainSet) return 'host-prefix-domain';
    const pathAttr = entry.attrs
      .map(a => (a.indexOf('=') >= 0 ? a.trim() : ''))
      .find(a => a.slice(0, a.indexOf('=')).trim().toLowerCase() === 'path');
    const pathVal = pathAttr ? pathAttr.slice(pathAttr.indexOf('=') + 1).trim() : '';
    if (pathVal !== '/') return 'host-prefix-path';
    return null;
  }
  if (n.startsWith('__Secure-')) {
    if (!isSecureResponse || !entry.secure) return 'secure-prefix-not-secure';
    return null;
  }
  return null;
}

// 从原始属性里去掉所有 SameSite 属性，返回保留原文的其余属性。

module.exports = {
  parseSetCookieEntry,
  extractSetCookieHeaders,
  MULTI_PART_SUFFIX,
  registrableDomain,
  hostOf,
  isThirdPartyContext,
  cookiePrefixViolation,
};
