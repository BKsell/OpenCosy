'use strict';

// referrerguard.js —— Referrer-Policy 与 document.referrer 裁剪裁决内核。
//
// 威胁模型：
//   1. 默认 referrer 可能把完整 URL（含会话 token、搜索词、订单号）泄露给第三方资源；
//   2. HTTPS→HTTP 降级默认仍可能带 origin 之外的信息；
//   3. cross-origin 导航/子资源拿到完整路径与查询；
//   4. 第三方脚本读 document.referrer 做回流追踪；
//   5. no-referrer-when-downgrade 这种宽松策略在现代隐私模型下不可接受。
//
// 本模块根据策略 + 请求上下文（同源/跨源/降级/导航类型）计算实际应发送的 Referer
// 头与暴露给页面的 document.referrer。纯逻辑。

const REF_POLICY = Object.freeze({
  NO_REFERRER: 'no-referrer',
  NO_REFERRER_WHEN_DOWNGRADE: 'no-referrer-when-downgrade',
  ORIGIN: 'origin',
  ORIGIN_WHEN_CROSS_ORIGIN: 'origin-when-cross-origin',
  SAME_ORIGIN: 'same-origin',
  STRICT_ORIGIN: 'strict-origin',
  STRICT_ORIGIN_WHEN_CROSS_ORIGIN: 'strict-origin-when-cross-origin',
  UNSAFE_URL: 'unsafe-url',
});

const REF_OUTCOME = Object.freeze({
  FULL: 'full',
  ORIGIN_ONLY: 'origin-only',
  EMPTY: 'empty',
});

function defaultReferrerPolicyChoice() {
  // 现代浏览器默认即 strict-origin-when-cross-origin，这里作为最严可用默认。
  return REF_POLICY.STRICT_ORIGIN_WHEN_CROSS_ORIGIN;
}

function parseOrigin(url) {
  if (typeof url !== 'string') return '';
  const colon = url.indexOf(':');
  if (colon <= 0) return '';
  const scheme = url.slice(0, colon).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  let rest = url.slice(colon + 1);
  if (rest.indexOf('//') === 0) rest = rest.slice(2);
  let host = rest;
  for (const ch of ['/', '?', '#']) {
    const p = host.indexOf(ch);
    if (p >= 0) host = host.slice(0, p);
  }
  return scheme + '://' + host.toLowerCase();
}

function isDowngrade(fromUrl, toUrl) {
  return parseOrigin(fromUrl).indexOf('https://') === 0 && parseOrigin(toUrl).indexOf('http://') === 0;
}

function sameOrigin(aUrl, bUrl) {
  const a = parseOrigin(aUrl);
  const b = parseOrigin(bUrl);
  return a !== '' && a === b;
}

// resolveReferrer 计算 Referer 头取值。
// ctx: {from, to, isNavigation} ；policy 为站点声明的策略。
function resolveReferrer(policy, from, to) {
  const p = policy || defaultReferrerPolicyChoice();
  const origin = parseOrigin(from);
  const cross = !sameOrigin(from, to);
  const downgrade = isDowngrade(from, to);

  switch (p) {
    case REF_POLICY.NO_REFERRER:
      return { outcome: REF_OUTCOME.EMPTY, value: '' };
    case REF_POLICY.UNSAFE_URL:
      return { outcome: REF_OUTCOME.FULL, value: from };
    case REF_POLICY.ORIGIN:
      return { outcome: REF_OUTCOME.ORIGIN_ONLY, value: origin };
    case REF_POLICY.SAME_ORIGIN:
      return cross ? { outcome: REF_OUTCOME.EMPTY, value: '' }
        : { outcome: REF_OUTCOME.FULL, value: from };
    case REF_POLICY.STRICT_ORIGIN:
      return downgrade ? { outcome: REF_OUTCOME.EMPTY, value: '' }
        : { outcome: REF_OUTCOME.ORIGIN_ONLY, value: origin };
    case REF_POLICY.ORIGIN_WHEN_CROSS_ORIGIN:
      return cross ? { outcome: REF_OUTCOME.ORIGIN_ONLY, value: origin }
        : { outcome: REF_OUTCOME.FULL, value: from };
    case REF_POLICY.NO_REFERRER_WHEN_DOWNGRADE:
      return downgrade ? { outcome: REF_OUTCOME.EMPTY, value: '' }
        : { outcome: REF_OUTCOME.FULL, value: from };
    case REF_POLICY.STRICT_ORIGIN_WHEN_CROSS_ORIGIN:
    default:
      if (downgrade) return { outcome: REF_OUTCOME.EMPTY, value: '' };
      if (cross) return { outcome: REF_OUTCOME.ORIGIN_ONLY, value: origin };
      return { outcome: REF_OUTCOME.FULL, value: from };
  }
}

// policyStrength 给策略一个“隐私强度”分，便于审计比较谁更严。
function policyStrength(policy) {
  switch (policy) {
    case REF_POLICY.NO_REFERRER: return 8;
    case REF_POLICY.SAME_ORIGIN: return 7;
    case REF_POLICY.STRICT_ORIGIN_WHEN_CROSS_ORIGIN: return 6;
    case REF_POLICY.STRICT_ORIGIN: return 5;
    case REF_POLICY.ORIGIN_WHEN_CROSS_ORIGIN: return 4;
    case REF_POLICY.ORIGIN: return 3;
    case REF_POLICY.NO_REFERRER_WHEN_DOWNGRADE: return 2;
    case REF_POLICY.UNSAFE_URL: return 1;
    default: return 0;
  }
}

// stripTrackingParams 删除常见回流追踪参数（纯字符键比较，不用正则）。
const TRACKING_KEYS = Object.freeze([
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'gclid', 'fbclid', 'mc_eid', 'mc_cid', 'spm', 'ref', 'referrer',
]);

function stripTrackingParams(url) {
  if (typeof url !== 'string') return url;
  const q = url.indexOf('?');
  if (q < 0) return url;
  const head = url.slice(0, q);
  let tail = url.slice(q + 1);
  let hash = '';
  const h = tail.indexOf('#');
  if (h >= 0) { hash = tail.slice(h); tail = tail.slice(0, h); }
  const pairs = tail.split('&');
  const kept = [];
  for (const pair of pairs) {
    if (pair === '') continue;
    const eq = pair.indexOf('=');
    const key = (eq >= 0 ? pair.slice(0, eq) : pair).toLowerCase();
    if (TRACKING_KEYS.indexOf(key) < 0) kept.push(pair);
  }
  const query = kept.length ? '?' + kept.join('&') : '';
  return head + query + hash;
}

module.exports = {
  REF_POLICY, REF_OUTCOME,
  defaultReferrerPolicyChoice, parseOrigin, sameOrigin, isDowngrade,
  resolveReferrer, policyStrength, stripTrackingParams, TRACKING_KEYS,
};
