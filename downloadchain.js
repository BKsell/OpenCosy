'use strict';

const MAX_CHAIN_HOPS = 20;
const MAX_HOP_URL_CHARS = 8192;

const VERDICT = {
  OK: 'ok',
  BLOCK: 'block',
};

const REASON = {
  OK: 'ok',
  NO_CHAIN: 'no-chain',
  BAD_SHAPE: 'bad-shape',
  TOO_LONG: 'chain-too-long',
  BAD_URL: 'bad-url',
  BAD_SCHEME: 'bad-scheme',
  USERINFO: 'userinfo',
  EMPTY_HOST: 'empty-host',
  BAD_HOST: 'bad-host',
  HTTPS_DOWNGRADE: 'https-downgrade',
};

function inspectDownloadChainHop(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_HOP_URL_CHARS) {
    return { ok: false, reason: REASON.BAD_URL, scheme: '', host: '' };
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: REASON.BAD_URL, scheme: '', host: '' };
  }
  const scheme = parsed.protocol.replace(':', '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    return { ok: false, reason: REASON.BAD_SCHEME, scheme, host: '' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: REASON.USERINFO, scheme, host: '' };
  }
  if (!parsed.hostname) {
    return { ok: false, reason: REASON.EMPTY_HOST, scheme, host: '' };
  }
  const host = parsed.hostname.toLowerCase();
  if (!validHostLabels(host)) {
    return { ok: false, reason: REASON.BAD_HOST, scheme, host: '' };
  }
  return { ok: true, reason: REASON.OK, scheme, host };
}

function validHostLabels(host) {
  if (host.length === 0 || host.length > 253) {
    return false;
  }
  const labels = host.split('.');
  if (labels.length < 2) {
    return false;
  }
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      return false;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
    for (const ch of label) {
      const ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch === '-' || ch === '_';
      if (!ok) {
        return false;
      }
    }
  }
  const last = labels[labels.length - 1];
  for (const ch of last) {
    if (ch >= '0' && ch <= '9') {
      return false;
    }
  }
  return true;
}

function analyzeDownloadChain(chain) {
  if (chain === null || chain === undefined) {
    return { verdict: VERDICT.OK, reason: REASON.NO_CHAIN, hops: 0, finalHost: '', finalScheme: '', downgraded: false };
  }
  if (!Array.isArray(chain)) {
    return { verdict: VERDICT.BLOCK, reason: REASON.BAD_SHAPE, hops: 0, finalHost: '', finalScheme: '', downgraded: false };
  }
  if (chain.length === 0) {
    return { verdict: VERDICT.OK, reason: REASON.NO_CHAIN, hops: 0, finalHost: '', finalScheme: '', downgraded: false };
  }
  if (chain.length > MAX_CHAIN_HOPS) {
    return { verdict: VERDICT.BLOCK, reason: REASON.TOO_LONG, hops: chain.length, finalHost: '', finalScheme: '', downgraded: false };
  }
  let prevScheme = '';
  let finalHost = '';
  let finalScheme = '';
  for (let i = 0; i < chain.length; i += 1) {
    const hop = inspectDownloadChainHop(chain[i]);
    if (!hop.ok) {
      return { verdict: VERDICT.BLOCK, reason: hop.reason, hops: chain.length, finalHost, finalScheme, downgraded: false };
    }
    if (hop.scheme === 'http' && prevScheme === 'https') {
      return { verdict: VERDICT.BLOCK, reason: REASON.HTTPS_DOWNGRADE, hops: chain.length, finalHost: hop.host, finalScheme: hop.scheme, downgraded: true };
    }
    prevScheme = hop.scheme;
    finalHost = hop.host;
    finalScheme = hop.scheme;
  }
  return { verdict: VERDICT.OK, reason: REASON.OK, hops: chain.length, finalHost, finalScheme, downgraded: false };
}

function describeDownloadChain(result) {
  const reason = result && result.reason;
  switch (reason) {
    case REASON.OK:
      return '重定向链通过';
    case REASON.NO_CHAIN:
      return '无重定向链信息';
    case REASON.BAD_SHAPE:
      return '重定向链结构不合法';
    case REASON.TOO_LONG:
      return '重定向次数超过 20 跳上限';
    case REASON.BAD_URL:
      return '重定向链含非法或超长地址';
    case REASON.BAD_SCHEME:
      return '重定向链出现非 http/https 协议';
    case REASON.USERINFO:
      return '重定向链地址含内嵌凭据';
    case REASON.EMPTY_HOST:
      return '重定向链地址缺少主机名';
    case REASON.BAD_HOST:
      return '重定向链主机名不符合 DNS 标签规则';
    case REASON.HTTPS_DOWNGRADE:
      return '重定向从 https 降级到 http';
    default:
      return '重定向链未通过安全校验';
  }
}

module.exports = {
  MAX_CHAIN_HOPS,
  MAX_HOP_URL_CHARS,
  VERDICT,
  REASON,
  validHostLabels,
  inspectDownloadChainHop,
  analyzeDownloadChain,
  describeDownloadChain,
};
