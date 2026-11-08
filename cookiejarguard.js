'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'cookie-jar-empty',
  BAD_DOMAIN: 'cookie-jar-bad-domain',
  PUBLIC_SUFFIX: 'cookie-jar-public-suffix',
  TOO_LARGE: 'cookie-jar-too-large',
  ATTRIBUTE_CONFLICT: 'cookie-jar-attribute-conflict',
  PLAINTEXT_COOKIE: 'cookie-jar-plaintext',
};

const MAX_BYTES = 4096;
const MAX_COOKIES = 180;
const PUBLIC_SUFFIX = ['com', 'net', 'org', 'co.uk', 'github.io', 'herokuapp.com'];

function evaluateCookieJar(cookies, options) {
  const opts = options || {};
  const list = Array.isArray(cookies) ? cookies : [];
  if (list.length === 0) return { ok: true, blocked: false, reason: REASON.EMPTY, accepted: 0 };
  if (list.length > MAX_COOKIES) {
    return { ok: false, blocked: true, reason: REASON.TOO_LARGE, count: list.length, limit: MAX_COOKIES };
  }
  let bytes = 0;
  for (const cookie of list) {
    const item = cookie || {};
    const domain = String(item.domain || '').toLowerCase().replace(/^\./, '');
    const name = String(item.name || '');
    const value = String(item.value || '');
    if (name === '') return { ok: false, blocked: true, reason: REASON.EMPTY, field: 'name' };
    bytes += name.length + value.length + 2;
    if (bytes > MAX_BYTES) {
      return { ok: false, blocked: true, reason: REASON.TOO_LARGE, bytes, limit: MAX_BYTES };
    }
    if (domain === '') continue;
    if (publicSuffixOf(domain)) {
      return { ok: false, blocked: true, reason: REASON.PUBLIC_SUFFIX, domain };
    }
    if (domain.startsWith('-') || domain.endsWith('-') || !/^[a-z0-9.-]+$/.test(domain)) {
      return { ok: false, blocked: true, reason: REASON.BAD_DOMAIN, domain: domain.slice(0, 48) };
    }
    if (item.sameSite === 'none' && item.secure !== true) {
      return { ok: false, blocked: true, reason: REASON.ATTRIBUTE_CONFLICT, cookie: name.slice(0, 32) };
    }
    if (item.secure === true && opts.siteHttpsOnly === true && String(item.origin || '').startsWith('http://')) {
      return { ok: false, blocked: true, reason: REASON.PLAINTEXT_COOKIE, cookie: name.slice(0, 32) };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, accepted: list.length, bytes };
}

function publicSuffixOf(domain) {
  const parts = domain.split('.');
  if (parts.length < 2) return true;
  const tail2 = parts.slice(-2).join('.');
  const tail3 = parts.slice(-3).join('.');
  return PUBLIC_SUFFIX.includes(tail2) || PUBLIC_SUFFIX.includes(tail3);
}

module.exports = {
  REASON,
  MAX_BYTES,
  MAX_COOKIES,
  PUBLIC_SUFFIX,
  evaluateCookieJar,
  publicSuffixOf,
};
