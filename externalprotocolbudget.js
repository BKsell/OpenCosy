'use strict';

const REASON = Object.freeze({
  OK: 'ok',
  BLOCKED_SCHEME: 'blocked-scheme',
  EMPTY_TARGET: 'empty-target',
  CONTROL_CHAR: 'control-char',
  TOO_LONG: 'too-long',
  USERINFO: 'userinfo',
  FLOOD: 'flood',
  SCHEME_FLOOD: 'scheme-flood',
});

const DEFAULT_POLICY = Object.freeze({
  windowMs: 60000,
  maxPerOrigin: 3,
  maxPerScheme: 6,
  maxTargetLength: 2048,
});

const ALWAYS_BLOCKED = new Set([
  'javascript', 'data', 'vbscript', 'file', 'about', 'blob', 'chrome',
  'chrome-extension', 'devtools', 'filesystem', 'ms-msdt', 'search-ms',
]);

function parseTarget(rawUrl) {
  if (typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  return parsed;
}

function scrubTarget(rawUrl) {
  if (typeof rawUrl !== 'string') {
    return { ok: false, reason: REASON.EMPTY_TARGET, target: '' };
  }
  const trimmed = rawUrl.trim();
  if (!trimmed) return { ok: false, reason: REASON.EMPTY_TARGET, target: '' };
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    return { ok: false, reason: REASON.CONTROL_CHAR, target: '' };
  }
  if (trimmed.length > DEFAULT_POLICY.maxTargetLength) {
    return { ok: false, reason: REASON.TOO_LONG, target: '' };
  }
  const parsed = parseTarget(trimmed);
  if (!parsed) return { ok: false, reason: REASON.BLOCKED_SCHEME, target: '' };
  if (parsed.username || parsed.password) {
    return { ok: false, reason: REASON.USERINFO, target: '' };
  }
  return { ok: true, reason: REASON.OK, target: parsed.href, parsed };
}

function normalizeOrigin(origin) {
  if (typeof origin !== 'string' || !origin.trim()) return '';
  return origin.trim().toLowerCase().slice(0, 253);
}

function createExternalBudget(policy = {}) {
  const cfg = {
    windowMs: Number(policy.windowMs) || DEFAULT_POLICY.windowMs,
    maxPerOrigin: Number(policy.maxPerOrigin) || DEFAULT_POLICY.maxPerOrigin,
    maxPerScheme: Number(policy.maxPerScheme) || DEFAULT_POLICY.maxPerScheme,
  };
  const originTimes = new Map();
  const schemeTimes = new Map();

  function prune(list, now) {
    const cutoff = now - cfg.windowMs;
    while (list.length && list[0] <= cutoff) list.shift();
  }

  function judge(input = {}) {
    const now = Number.isFinite(input.now) ? input.now : Date.now();
    const scrub = scrubTarget(input.url);
    if (!scrub.ok) {
      return { allowed: false, reason: scrub.reason, retryAfterMs: 0, target: '' };
    }
    const scheme = scrub.parsed.protocol.replace(':', '').toLowerCase();
    if (!scheme || ALWAYS_BLOCKED.has(scheme)) {
      return { allowed: false, reason: REASON.BLOCKED_SCHEME, retryAfterMs: 0, target: scrub.target };
    }
    const origin = normalizeOrigin(input.origin);
    if (!origin) {
      return { allowed: false, reason: REASON.EMPTY_TARGET, retryAfterMs: 0, target: scrub.target };
    }

    const originKey = `${origin}|${scheme}`;
    const originList = originTimes.get(originKey) || [];
    const schemeList = schemeTimes.get(scheme) || [];
    prune(originList, now);
    prune(schemeList, now);

    if (originList.length >= cfg.maxPerOrigin) {
      const retryAfterMs = Math.max(0, originList[0] + cfg.windowMs - now);
      originTimes.set(originKey, originList);
      return { allowed: false, reason: REASON.FLOOD, retryAfterMs, target: scrub.target };
    }
    if (schemeList.length >= cfg.maxPerScheme) {
      const retryAfterMs = Math.max(0, schemeList[0] + cfg.windowMs - now);
      schemeTimes.set(scheme, schemeList);
      return { allowed: false, reason: REASON.SCHEME_FLOOD, retryAfterMs, target: scrub.target };
    }

    originList.push(now);
    schemeList.push(now);
    originTimes.set(originKey, originList);
    schemeTimes.set(scheme, schemeList);
    return { allowed: true, reason: REASON.OK, retryAfterMs: 0, target: scrub.target, scheme };
  }

  function reset() {
    originTimes.clear();
    schemeTimes.clear();
  }

  function snapshot(now = Date.now()) {
    const origins = [];
    for (const [key, list] of originTimes.entries()) {
      const fresh = list.filter((t) => t > now - cfg.windowMs);
      if (fresh.length) origins.push({ key, count: fresh.length });
    }
    const schemes = [];
    for (const [key, list] of schemeTimes.entries()) {
      const fresh = list.filter((t) => t > now - cfg.windowMs);
      if (fresh.length) schemes.push({ key, count: fresh.length });
    }
    return { origins, schemes, policy: { ...cfg } };
  }

  return { judge, reset, snapshot };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK: return '允许';
    case REASON.BLOCKED_SCHEME: return '协议不在可唤起白名单';
    case REASON.EMPTY_TARGET: return '外部唤起目标为空或来源缺失';
    case REASON.CONTROL_CHAR: return '目标含控制字符';
    case REASON.TOO_LONG: return '目标超长';
    case REASON.USERINFO: return '目标内嵌账号口令';
    case REASON.FLOOD: return '同一来源唤起过于频繁';
    case REASON.SCHEME_FLOOD: return '该协议唤起次数超限';
    default: return '未知原因';
  }
}

module.exports = {
  REASON,
  DEFAULT_POLICY,
  ALWAYS_BLOCKED,
  scrubTarget,
  createExternalBudget,
  describeReason,
};
