'use strict';

// fencedframeguard.js —— <fencedframe>/URN UUID 围栏框架加载与通信裁决内核。
//
// 威胁模型：
//   1. fencedframe 承载不透明 URN（urn:uuid:...）且设计上与外层页面隔离，但仍可被用作
//      跨站广告/存储分区的渲染落脚点；三方站点可借此在围栏内运行脚本、探测尺寸；
//   2. 通过 resolveURN/ fenced frame config 传入 http 或外部 scheme，绕过 https-only；
//   3. 围栏与外层通过 postMessage 通信若不限制 targetOrigin，围栏内容可把数据外抛；
//   4. 用 resolveURN 解析非 urn:uuid 的普通 https URL，等于把任意页面塞进高权限围栏；
//   5. 嵌套围栏、超大/畸形 config 是脏数据。
//
// 纯逻辑。

const FF_ALLOW = 'allow';
const FF_DENY = 'deny';

const FF_REASON = Object.freeze({
  BAD_CONTEXT: 'ff-bad-context',
  INSECURE_ORIGIN: 'ff-insecure-origin',
  CROSS_ORIGIN_SUBFRAME: 'ff-cross-origin-subframe',
  THIRD_PARTY_NOT_ALLOWED: 'ff-third-party-not-allowed',
  NOT_A_FENCE_CONFIG: 'ff-not-a-fence-config',
  BAD_URN: 'ff-bad-urn',
  INSECURE_RESOLVED_URL: 'ff-insecure-resolved-url',
  EXTERNAL_SCHEME: 'ff-external-scheme',
  NESTED_FENCE: 'ff-nested-fence',
  POSTMESSAGE_WILDCARD: 'ff-postmessage-wildcard',
  CONFIG_TOO_LARGE: 'ff-config-too-large',
});

const FF_MAX_CONFIG_BYTES = 16 * 1024;

function defaultFencedFramePolicy() {
  return {
    requireHttps: true,
    blockCrossOriginSubframe: true,
    allowThirdPartyFence: false,
    allowedEmbedderSites: [],
    requireUrnUuid: true,
    blockNestedFence: true,
    requireExplicitPostMessageTarget: true,
    maxConfigBytes: FF_MAX_CONFIG_BYTES,
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

function hexCount(s, start, len) {
  if (start + len > s.length) return false;
  for (let i = start; i < start + len; i++) {
    const c = s.charCodeAt(i);
    const d = (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
    if (!d) return false;
  }
  return true;
}

// isUrnUuid 判断是否 urn:uuid:8-4-4-4-12（纯字符）。
function isUrnUuid(token) {
  if (typeof token !== 'string') return false;
  const p = 'urn:uuid:';
  if (token.slice(0, p.length).toLowerCase() !== p) return false;
  const body = token.slice(p.length);
  const parts = body.split('-');
  if (parts.length !== 5) return false;
  return hexCount(parts[0], 0, 8) && hexCount(parts[1], 0, 4) && hexCount(parts[2], 0, 4) &&
    hexCount(parts[3], 0, 4) && hexCount(parts[4], 0, 12);
}

function siteOf(url) {
  if (typeof url !== 'string') return '';
  const i = url.indexOf('://');
  if (i <= 0) return '';
  let rest = url.slice(i + 3);
  for (const ch of ['/', '?', '#', ':']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  const labels = rest.toLowerCase().split('.');
  if (labels.length < 2) return rest.toLowerCase();
  return labels.slice(-2).join('.');
}

class FencedFrameGuard {
  constructor(policy) {
    this.policy = policy || defaultFencedFramePolicy();
  }

  _gate(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return FF_REASON.BAD_CONTEXT;
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return FF_REASON.INSECURE_ORIGIN;
    if (pol.blockCrossOriginSubframe && ctx.isTopFrame === false && ctx.embeddingFence !== true) {
      return FF_REASON.CROSS_ORIGIN_SUBFRAME;
    }
    return '';
  }

  // decideLoad 裁决围栏加载。config: {urn|resolvedURL, nestedInFence}。
  decideLoad(ctx, config) {
    const bad = this._gate(ctx);
    if (bad) return { decision: FF_DENY, reason: bad };
    const pol = this.policy;
    if (!config || typeof config !== 'object') return { decision: FF_DENY, reason: FF_REASON.NOT_A_FENCE_CONFIG };
    if (pol.blockNestedFence && config.nestedInFence === true) {
      return { decision: FF_DENY, reason: FF_REASON.NESTED_FENCE };
    }

    const urn = config.urn;
    const resolved = typeof config.resolvedURL === 'string' ? config.resolvedURL : '';
    if (typeof urn === 'string' && urn.length > 0) {
      if (pol.requireUrnUuid && !isUrnUuid(urn)) return { decision: FF_DENY, reason: FF_REASON.BAD_URN, urn };
    } else if (resolved.length > 0) {
      const scheme = resolved.indexOf(':') > 0 ? resolved.slice(0, resolved.indexOf(':')).toLowerCase() : '';
      if (scheme !== 'https' && scheme !== 'http') return { decision: FF_DENY, reason: FF_REASON.EXTERNAL_SCHEME, scheme };
      if (pol.requireHttps && scheme !== 'https') return { decision: FF_DENY, reason: FF_REASON.INSECURE_RESOLVED_URL };
      // 解析到普通 URL 时仍按三方嵌入站点白名单裁决。
      if (!pol.allowThirdPartyFence) {
        const target = siteOf(resolved);
        const emb = siteOf(ctx.origin);
        const ok = pol.allowedEmbedderSites.some((s) => target === s || target.endsWith('.' + s));
        if (target !== emb && !ok) return { decision: FF_DENY, reason: FF_REASON.THIRD_PARTY_NOT_ALLOWED, site: target };
      }
    } else {
      return { decision: FF_DENY, reason: FF_REASON.NOT_A_FENCE_CONFIG };
    }

    if (typeof config.serialized === 'string' && byteLen(config.serialized) > pol.maxConfigBytes) {
      return { decision: FF_DENY, reason: FF_REASON.CONFIG_TOO_LARGE };
    }
    return { decision: FF_ALLOW, reason: '' };
  }

  // decidePostMessage 裁决围栏内外通信。
  decidePostMessage(message) {
    const pol = this.policy;
    if (pol.requireExplicitPostMessageTarget &&
        (!message || message.targetOrigin === '*' || message.targetOrigin === undefined)) {
      return { decision: FF_DENY, reason: FF_REASON.POSTMESSAGE_WILDCARD };
    }
    return { decision: FF_ALLOW, reason: '' };
  }
}

module.exports = {
  FF_ALLOW, FF_DENY, FF_REASON, FF_MAX_CONFIG_BYTES,
  defaultFencedFramePolicy, isUrnUuid, siteOf, byteLen, FencedFrameGuard,
};
