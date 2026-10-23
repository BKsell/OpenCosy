'use strict';

// interestgroupguard.js —— Protected Audience / FLEDGE（joinAdInterestGroup/runAdAuction）裁决内核。
//
// 威胁模型：
//   1. joinAdInterestGroup 让买方在浏览器本地长期保存兴趣组（owner 域名 + 出价/渲染 URL +
//      userBiddingSignals），是无三方 Cookie 的跨站再营销内核；
//   2. 兴趣组 lifetime 被设到数年，ads 用极短名高频更新形成持久 ID；
//   3. biddingLogicURL/renderURL/trustedScoringSignalsURL 指向非 https 或跨 owner 主机，
//      worklet 可在围栏里运行并外联拉取打分信号（变相 SSRF/信标）；
//   4. userBiddingSignals 体积过大或含每用户唯一键，把可识别数据塞进本地竞价；
//   5. runAdAuction 的 seller 在三方 iframe 触发，且 seller 与 decisionLogicURL 不同源。
//
// 纯逻辑。

const IG_ALLOW = 'allow';
const IG_DENY = 'deny';

const IG_REASON = Object.freeze({
  BAD_CONTEXT: 'ig-bad-context',
  INSECURE_ORIGIN: 'ig-insecure-origin',
  THIRD_PARTY_CONTEXT: 'ig-third-party-context',
  BAD_OWNER: 'ig-bad-owner',
  OWNER_CROSS_SITE: 'ig-owner-cross-site',
  BAD_LIFETIME: 'ig-bad-lifetime',
  LIFETIME_TOO_LONG: 'ig-lifetime-too-long',
  INSECURE_LOGIC_URL: 'ig-insecure-logic-url',
  LOGIC_CROSS_OWNER: 'ig-logic-cross-owner',
  BAD_RENDER_URL: 'ig-bad-render-url',
  RENDER_EXTERNAL_SCHEME: 'ig-render-external-scheme',
  SIGNALS_TOO_LARGE: 'ig-signals-too-large',
  TOO_MANY_GROUPS_PER_OWNER: 'ig-too-many-groups-per-owner',
  SELLER_LOGIC_CROSS_SITE: 'ig-seller-logic-cross-site',
});

const IG_MAX_LIFETIME_DAYS = 30;
const IG_MAX_SIGNALS_BYTES = 8 * 1024;
const IG_MAX_GROUPS_PER_OWNER = 200;

function defaultInterestGroupPolicy() {
  return {
    requireHttps: true,
    allowInThirdPartyContext: true, // join 本身就是三方 API，但仍受 owner 校验约束
    allowedJoinSites: [],
    requireHttpsLogicUrls: true,
    requireLogicSameOwner: true,
    maxLifetimeSeconds: IG_MAX_LIFETIME_DAYS * 24 * 3600,
    maxSignalsBytes: IG_MAX_SIGNALS_BYTES,
    maxGroupsPerOwner: IG_MAX_GROUPS_PER_OWNER,
  };
}

function byteLen(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    n += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
  }
  return n;
}

function hostOf(url) {
  if (typeof url !== 'string') return '';
  const i = url.indexOf('://');
  if (i <= 0) return '';
  let rest = url.slice(i + 3);
  for (const ch of ['/', '?', '#']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  if (rest.indexOf('@') >= 0) rest = rest.slice(rest.lastIndexOf('@') + 1);
  if (rest.indexOf('[') === 0) {
    const rb = rest.indexOf(']');
    rest = rb > 0 ? rest.slice(1, rb) : rest;
  } else {
    const pc = rest.lastIndexOf(':');
    if (pc > 0) rest = rest.slice(0, pc);
  }
  return rest.toLowerCase();
}
function schemeOf(url) {
  if (typeof url !== 'string') return '';
  const c = url.indexOf(':');
  return c > 0 ? url.slice(0, c).toLowerCase() : '';
}
function regDomain(host) {
  const labels = host.split('.');
  return labels.length >= 2 ? labels.slice(-2).join('.') : host;
}

class InterestGroupGuard {
  constructor(policy) {
    this.policy = policy || defaultInterestGroupPolicy();
    this.groupCounts = new Map();
  }

  // decideJoin 裁决 navigator.joinAdInterestGroup(group)。
  // ctx: {origin, isTopFrame}；group: {owner, name, lifetimeSeconds, biddingLogicURL,
  //   ads:[{renderURL}], userBiddingSignals(JSON string)}
  decideJoin(ctx, group) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') {
      return { decision: IG_DENY, reason: IG_REASON.BAD_CONTEXT };
    }
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) {
      return { decision: IG_DENY, reason: IG_REASON.INSECURE_ORIGIN };
    }
    if (!pol.allowInThirdPartyContext && ctx.isTopFrame === false) {
      return { decision: IG_DENY, reason: IG_REASON.THIRD_PARTY_CONTEXT };
    }
    const g = group && typeof group === 'object' ? group : null;
    if (!g || typeof g.owner !== 'string') return { decision: IG_DENY, reason: IG_REASON.BAD_OWNER };

    const ownerHost = hostOf(g.owner);
    if (!ownerHost) return { decision: IG_DENY, reason: IG_REASON.BAD_OWNER };
    const callerReg = regDomain(hostOf(ctx.origin));
    const ownerReg = regDomain(ownerHost);
    if (callerReg !== ownerReg) {
      const ok = pol.allowedJoinSites.some((s) => callerReg === s || callerReg.endsWith('.' + s));
      if (!ok) return { decision: IG_DENY, reason: IG_REASON.OWNER_CROSS_SITE, owner: ownerReg, caller: callerReg };
    }

    const life = g.lifetimeSeconds;
    if (typeof life !== 'number' || !Number.isFinite(life) || life <= 0) {
      return { decision: IG_DENY, reason: IG_REASON.BAD_LIFETIME };
    }
    if (life > pol.maxLifetimeSeconds) {
      return { decision: IG_DENY, reason: IG_REASON.LIFETIME_TOO_LONG, lifetimeSeconds: life };
    }

    if (g.biddingLogicURL !== undefined) {
      const u = g.biddingLogicURL;
      if (schemeOf(u) !== 'https' && pol.requireHttpsLogicUrls) {
        return { decision: IG_DENY, reason: IG_REASON.INSECURE_LOGIC_URL, url: u };
      }
      if (pol.requireLogicSameOwner && regDomain(hostOf(u)) !== ownerReg) {
        return { decision: IG_DENY, reason: IG_REASON.LOGIC_CROSS_OWNER, url: u, owner: ownerReg };
      }
    }

    const ads = Array.isArray(g.ads) ? g.ads : [];
    for (let i = 0; i < ads.length; i++) {
      const ru = ads[i] && ads[i].renderURL;
      const sch = schemeOf(ru);
      if (sch !== 'https' && sch !== 'http') {
        return { decision: IG_DENY, reason: IG_REASON.RENDER_EXTERNAL_SCHEME, index: i, url: ru };
      }
      if (sch !== 'https') return { decision: IG_DENY, reason: IG_REASON.BAD_RENDER_URL, index: i, url: ru };
    }

    if (typeof g.userBiddingSignals === 'string' && byteLen(g.userBiddingSignals) > pol.maxSignalsBytes) {
      return { decision: IG_DENY, reason: IG_REASON.SIGNALS_TOO_LARGE, bytes: byteLen(g.userBiddingSignals) };
    }

    const n = this.groupCounts.get(ownerReg) || 0;
    if (n >= pol.maxGroupsPerOwner) return { decision: IG_DENY, reason: IG_REASON.TOO_MANY_GROUPS_PER_OWNER, owner: ownerReg };
    this.groupCounts.set(ownerReg, n + 1);
    return { decision: IG_ALLOW, reason: '', owner: ownerReg };
  }

  // decideAuction 裁决 runAdAuction(config)。seller 与 decisionLogicURL 必须同站、https。
  decideAuction(ctx, config) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: IG_DENY, reason: IG_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: IG_DENY, reason: IG_REASON.INSECURE_ORIGIN };
    const c = config && typeof config === 'object' ? config : null;
    if (!c || typeof c.seller !== 'string') return { decision: IG_DENY, reason: IG_REASON.BAD_OWNER };
    const sellerReg = regDomain(hostOf(c.seller));
    if (!sellerReg) return { decision: IG_DENY, reason: IG_REASON.BAD_OWNER };
    if (typeof c.decisionLogicURL === 'string') {
      const u = c.decisionLogicURL;
      if (schemeOf(u) !== 'https') return { decision: IG_DENY, reason: IG_REASON.INSECURE_LOGIC_URL, url: u };
      if (regDomain(hostOf(u)) !== sellerReg) {
        return { decision: IG_DENY, reason: IG_REASON.SELLER_LOGIC_CROSS_SITE, url: u, seller: sellerReg };
      }
    }
    return { decision: IG_ALLOW, reason: '', seller: sellerReg };
  }
}

module.exports = {
  IG_ALLOW, IG_DENY, IG_REASON,
  IG_MAX_LIFETIME_DAYS, IG_MAX_SIGNALS_BYTES, IG_MAX_GROUPS_PER_OWNER,
  defaultInterestGroupPolicy, byteLen, hostOf, schemeOf, regDomain, InterestGroupGuard,
};
