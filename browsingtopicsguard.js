'use strict';

// browsingtopicsguard.js —— Topics API（document.browsingTopics()）兴趣画像裁决内核。
//
// 威胁模型：
//   1. browsingTopics() 返回按浏览历史推断的高维兴趣分类，第三方在多个站点调用即可拼接
//      跨站画像；调用本身还会把当前页面观察记录进 epoch 画像；
//   2. 第三方上下文（iframe/嵌入脚本/子资源）调用是画像外泄的主要路径；
//   3. 高敏主题（医疗、财务、性取向、宗教、政治、未成年相关）即使被推断也不应外抛；
//   4. 每页调用次数/返回主题数无上限会放大指纹熵；
//   5. 用 observe/skip 标记操纵画像（广告方塞入或抹除主题）属于画像投毒。
//
// 纯逻辑。

const BT_ALLOW = 'allow';
const BT_DENY = 'deny';
const BT_FILTER = 'filter'; // 允许调用但过滤敏感主题

const BT_REASON = Object.freeze({
  BAD_CONTEXT: 'tp-bad-context',
  INSECURE_ORIGIN: 'tp-insecure-origin',
  API_DISABLED: 'tp-api-disabled',
  THIRD_PARTY_CONTEXT: 'tp-third-party-context',
  SENSITIVE_TOPIC_PRESENT: 'tp-sensitive-topic-present',
  TOO_MANY_TOPICS: 'tp-too-many-topics',
  RATE_LIMIT: 'tp-rate-limit',
  OBSERVE_MANIPULATION: 'tp-observe-manipulation',
});

// Chrome Topics 分类里的高敏区段（按 taxv2 近似的主题号区间/显式号）。
// 这里用区间表达健康/财务/身份等大类，避免硬编码全表。
const BT_SENSITIVE_RANGES = Object.freeze([
  [144, 144], // 男性健康
  [149, 150], // 生殖/性健康
  [162, 162], // 心理健康
  [175, 175], // 慢性疼痛/疾病管理
  [182, 182], // 癌症
  [236, 238], // 银行业务/借贷/债务管理
  [248, 249], // 保险/退休规划
  [432, 432], // 心理健康支持（近似）
]);

function defaultTopicsPolicy() {
  return {
    requireHttps: true,
    apiEnabled: true,
    allowInThirdPartyContext: false,
    allowedCallerSites: [],
    filterSensitiveTopics: true,
    blockIfAnySensitive: false, // true=含敏感主题直接整单拒绝；false=过滤后返回
    maxTopicsPerCall: 3,
    maxCallsPerPage: 2,
    blockObserveManipulation: true,
  };
}

function isSensitiveTopic(id) {
  if (typeof id !== 'number' || !Number.isInteger(id)) return false;
  for (const [lo, hi] of BT_SENSITIVE_RANGES) {
    if (id >= lo && id <= hi) return true;
  }
  return false;
}

function siteOf(origin) {
  if (typeof origin !== 'string') return '';
  const i = origin.indexOf('://');
  if (i <= 0) return '';
  let rest = origin.slice(i + 3);
  for (const ch of ['/', '?', '#', ':']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  const labels = rest.toLowerCase().split('.');
  return labels.length >= 2 ? labels.slice(-2).join('.') : rest.toLowerCase();
}

class BrowsingTopicsGuard {
  constructor(policy) {
    this.policy = policy || defaultTopicsPolicy();
    this.callsPerPage = new Map();
  }

  // decide 裁决一次 browsingTopics 调用。
  // ctx: {origin, isTopFrame, pageKey}
  // offer: {topics:[ids], observe?:bool, callerSite?}
  decide(ctx, offer) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') {
      return { decision: BT_DENY, reason: BT_REASON.BAD_CONTEXT };
    }
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) {
      return { decision: BT_DENY, reason: BT_REASON.INSECURE_ORIGIN };
    }
    if (!pol.apiEnabled) return { decision: BT_DENY, reason: BT_REASON.API_DISABLED };

    if (!pol.allowInThirdPartyContext && ctx.isTopFrame === false) {
      const caller = offer && offer.callerSite ? siteOf(String(offer.callerSite)) : siteOf(ctx.origin);
      const whitelisted = pol.allowedCallerSites.some((s) => caller === s || caller.endsWith('.' + s));
      if (!whitelisted) return { decision: BT_DENY, reason: BT_REASON.THIRD_PARTY_CONTEXT, callerSite: caller };
    }

    const topics = offer && Array.isArray(offer.topics) ? offer.topics : [];
    if (topics.length > pol.maxTopicsPerCall) {
      return { decision: BT_DENY, reason: BT_REASON.TOO_MANY_TOPICS, count: topics.length };
    }
    if (pol.blockObserveManipulation && offer && offer.observe === true && ctx.isTopFrame === false) {
      return { decision: BT_DENY, reason: BT_REASON.OBSERVE_MANIPULATION };
    }

    const sensitive = topics.filter((id) => isSensitiveTopic(id));
    if (sensitive.length > 0 && pol.blockIfAnySensitive) {
      return { decision: BT_DENY, reason: BT_REASON.SENSITIVE_TOPIC_PRESENT, topics: sensitive };
    }

    const key = ctx.pageKey || ctx.origin;
    const n = this.callsPerPage.get(key) || 0;
    if (n >= pol.maxCallsPerPage) return { decision: BT_DENY, reason: BT_REASON.RATE_LIMIT };
    this.callsPerPage.set(key, n + 1);

    if (sensitive.length > 0 && pol.filterSensitiveTopics) {
      return { decision: BT_FILTER, reason: '', topics: topics.filter((id) => !isSensitiveTopic(id)), filtered: sensitive };
    }
    return { decision: BT_ALLOW, reason: '', topics: topics.slice() };
  }

  resetPage(pageKey) {
    this.callsPerPage.delete(pageKey);
  }
}

module.exports = {
  BT_ALLOW, BT_DENY, BT_FILTER, BT_REASON, BT_SENSITIVE_RANGES,
  defaultTopicsPolicy, isSensitiveTopic, siteOf, BrowsingTopicsGuard,
};
