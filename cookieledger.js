'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

function loadCookieLedger() {
  if (d.cookieLedgerLoaded) return;
  d.cookieLedgerLoaded = true;
  try {
    d.cookieLedger.load(d.ledgerStore.readJSONStore(d.cookieLedgerStorePath, {}));
  } catch {}
}

function persistCookieLedger() {
  if (d.cookieLedgerSaveTimer) clearTimeout(d.cookieLedgerSaveTimer);
  d.cookieLedgerSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.cookieLedgerStorePath, d.cookieLedger.toJSON());
    } catch {}
  }, 300);
}

function normalizeCookieDomain(domain) {
  if (typeof domain !== 'string' || !domain) return '';
  return domain.startsWith('.') ? domain.slice(1) : domain;
}

function pickCookieFields(c) {
  return {
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    secure: !!c.secure,
    httpOnly: !!c.httpOnly,
    session: !!c.session,
    hostOnly: !!c.hostOnly,
    sameSite: c.sameSite || 'unspecified',
    expirationDate: typeof c.expirationDate === 'number' ? c.expirationDate : null,
  };
}

async function removeCookieEntry(cookie) {
  const host = normalizeCookieDomain(cookie.domain);
  const urlPath = cookie.path && cookie.path.startsWith('/') ? cookie.path : '/';
  let lastError = null;
  for (const scheme of cookieOriginSchemes(cookie)) {
    try {
      await d.session.defaultSession.cookies.remove(`${scheme}://${host}${urlPath}`, cookie.name);
      return;
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error('删除 Cookie 失败');
}

function cookieOriginSchemes(cookie) {
  // secure cookie 只能在 https 下删除；非 secure 的在两种 scheme 都试一次。
  return cookie.secure ? ['https'] : ['https', 'http'];
}

module.exports = { loadCookieLedger, persistCookieLedger, normalizeCookieDomain, pickCookieFields, removeCookieEntry, cookieOriginSchemes, bindDeps };
