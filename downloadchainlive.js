'use strict';

const MAX_LIVE_HOPS = 20;
const MAX_LIVE_URL_CHARS = 8192;

const VERDICT = {
  CONTINUE: 'continue',
  ABORT: 'abort',
};

const REASON = {
  OK: 'ok',
  NO_CHAIN: 'no-chain',
  BAD_SHAPE: 'bad-shape',
  TOO_MANY_HOPS: 'too-many-hops',
  BAD_URL: 'bad-url',
  BAD_SCHEME: 'bad-scheme',
  USERINFO: 'userinfo',
  EMPTY_HOST: 'empty-host',
  DOWNGRADE: 'https-downgrade',
};

function describeLiveChain(result) {
  if (!result) return '未知链路状态';
  switch (result.reason) {
    case REASON.OK:
      return `链路正常（${result.hopCount} 跳）`;
    case REASON.NO_CHAIN:
      return '尚无可校验的重定向链';
    case REASON.BAD_SHAPE:
      return '重定向链结构非法';
    case REASON.TOO_MANY_HOPS:
      return `重定向跳数超过上限（${MAX_LIVE_HOPS}）`;
    case REASON.BAD_URL:
      return `第 ${result.badIndex + 1} 跳地址无法解析`;
    case REASON.BAD_SCHEME:
      return `第 ${result.badIndex + 1} 跳不是 http/https`;
    case REASON.USERINFO:
      return `第 ${result.badIndex + 1} 跳地址包含用户信息`;
    case REASON.EMPTY_HOST:
      return `第 ${result.badIndex + 1} 跳地址缺少主机名`;
    case REASON.DOWNGRADE:
      return `第 ${result.badIndex + 1} 跳把 HTTPS 降级为明文 HTTP`;
    default:
      return '重定向链未通过校验';
  }
}

function inspectHop(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_LIVE_URL_CHARS) {
    return { ok: false, reason: REASON.BAD_URL };
  }
  for (let i = 0; i < raw.length; i += 1) {
    const code = raw.charCodeAt(i);
    if (code < 0x21 || code === 0x7f) {
      return { ok: false, reason: REASON.BAD_URL };
    }
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: REASON.BAD_URL };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { ok: false, reason: REASON.BAD_SCHEME };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: REASON.USERINFO };
  }
  if (!parsed.hostname) {
    return { ok: false, reason: REASON.EMPTY_HOST };
  }
  return { ok: true, https: parsed.protocol === 'https:', host: parsed.hostname.toLowerCase(), url: parsed.href };
}

function auditLiveChain(chain) {
  if (chain === null || chain === undefined) {
    return { verdict: VERDICT.CONTINUE, reason: REASON.NO_CHAIN, hopCount: 0, badIndex: -1, finalHost: '', finalUrl: '' };
  }
  if (!Array.isArray(chain)) {
    return { verdict: VERDICT.ABORT, reason: REASON.BAD_SHAPE, hopCount: 0, badIndex: -1, finalHost: '', finalUrl: '' };
  }
  if (chain.length === 0) {
    return { verdict: VERDICT.CONTINUE, reason: REASON.NO_CHAIN, hopCount: 0, badIndex: -1, finalHost: '', finalUrl: '' };
  }
  if (chain.length > MAX_LIVE_HOPS) {
    return { verdict: VERDICT.ABORT, reason: REASON.TOO_MANY_HOPS, hopCount: chain.length, badIndex: -1, finalHost: '', finalUrl: '' };
  }
  let previousHttps = null;
  let finalHost = '';
  let finalUrl = '';
  for (let i = 0; i < chain.length; i += 1) {
    const hop = inspectHop(chain[i]);
    if (!hop.ok) {
      return { verdict: VERDICT.ABORT, reason: hop.reason, hopCount: chain.length, badIndex: i, finalHost, finalUrl };
    }
    if (previousHttps === true && hop.https === false) {
      return { verdict: VERDICT.ABORT, reason: REASON.DOWNGRADE, hopCount: chain.length, badIndex: i, finalHost: hop.host, finalUrl: hop.url };
    }
    previousHttps = hop.https;
    finalHost = hop.host;
    finalUrl = hop.url;
  }
  return { verdict: VERDICT.CONTINUE, reason: REASON.OK, hopCount: chain.length, badIndex: -1, finalHost, finalUrl };
}

module.exports = {
  VERDICT,
  REASON,
  MAX_LIVE_HOPS,
  MAX_LIVE_URL_CHARS,
  auditLiveChain,
  describeLiveChain,
};
