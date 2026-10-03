'use strict';

// urlclean.js —— 链接追踪参数清洗与跳转包装解包（纯函数，可单测，不触网）。
//
// 现代浏览器（Firefox 严格模式、Safari）会在打开链接时剥离已知营销/跨站追踪
// 参数。这里提供一份保守的纯内核：
//
//   - 只删除“公认且不影响页面定位”的营销参数（utm_*、各平台 click id、
//     fbclid/gclid/ttclid 等），不碰 ref/from 这类可能参与登录回跳的功能参数；
//   - 保留 path、hash 路由与其余查询参数，参数顺序稳定（按首次出现重建）；
//   - 对常见“跳转包装”链接（google/url?q=、l.facebook.com/l.php?u=、
//     youtube redirect、t.cn 等）只在目标参数是合法 http(s) 时解包，失败原样返回；
//   - 非 http(s)（file、data、javascript、内部 scheme）一律原样返回，绝不清洗，
//     避免把内部协议或 mailto 改坏。

// 公认营销 / 跨站归因参数（精确匹配，小写）。
const TRACKING_PARAMS = Object.freeze(new Set([
  // Urchin / Google Analytics
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'utm_id', 'utm_name', 'utm_cid', 'utm_reader', 'utm_referrer', 'utm_social',
  'utm_social_type', 'utm_brand', 'utm_pubreferrer', 'utm_swu',
  // 各广告平台 click id
  'gclid', 'gclsrc', 'dclid', 'gbraid', 'wbraid', 'fbclid', 'msclkid',
  'yclid', 'ysclid', 'mc_cid', 'mc_eid', 'igshid', 'twclid', 'ttclid',
  'scid', 'sccid', 'kotclient', 'vero_id', 'vero_conv', 'zanpid',
  'wickedid', 'awc', 'campaign_id', 'ad_id', 'adset_id', 'placement',
  // HubSpot / Mailchimp / 其它营销系统
  '_hsenc', '_hsmi', 'hsctatracking', 'mkt_tok', 'oly_anon_id', 'oly_enc_id',
  // 站内分享 / 推荐统计（不参与内容定位）
  'share_id', 'share_medium', 'spm', 'scm',
]));

// 部分站点特有的追踪参数（按主机后缀匹配时才删，保守）。
const HOST_SPECIFIC_TRACKING = Object.freeze({
  'google.com': ['ved', 'ei', 'iflsrc', 'sxsrf'],
  'youtube.com': ['si', 'feature', 'pp'],
  'twitter.com': ['s', 't'],
  'x.com': ['s', 't'],
});

// 跳转包装：主机后缀 -> 承载真实地址的参数名（按优先级）。
const REDIRECT_WRAPPERS = Object.freeze([
  { suffix: 'google.com', pathIncludes: '/url', param: 'q' },
  { suffix: 'google.com.hk', pathIncludes: '/url', param: 'q' },
  { suffix: 'l.facebook.com', pathIncludes: '/l.php', param: 'u' },
  { suffix: 'facebook.com', pathIncludes: '/l.php', param: 'u' },
  { suffix: 'youtube.com', pathIncludes: '/redirect', param: 'q' },
  { suffix: 'm.youtube.com', pathIncludes: '/redirect', param: 'q' },
  { suffix: 'linkedin.com', pathIncludes: '/redirect', param: 'url' },
]);

function isWebUrl(raw) {
  return /^https?:\/\//i.test(String(raw || ''));
}

function hostSuffix(host) {
  const h = String(host || '').toLowerCase();
  for (const suffix of Object.keys(HOST_SPECIFIC_TRACKING)) {
    if (h === suffix || h.endsWith('.' + suffix)) {
      return suffix;
    }
  }
  return null;
}

// cleanUrl 删除已知追踪参数。返回 { url, changed, removedKeys }；
// 非 http(s) 或解析失败时原样返回。
function cleanUrl(raw) {
  const original = String(raw || '');
  if (!isWebUrl(original)) {
    return { url: original, changed: false, removedKeys: [] };
  }

  let u;
  try {
    u = new URL(original);
  } catch {
    return { url: original, changed: false, removedKeys: [] };
  }

  const suffix = hostSuffix(u.hostname);
  const hostParams = suffix ? new Set(HOST_SPECIFIC_TRACKING[suffix]) : null;

  const removed = [];
  const kept = [];
  // URLSearchParams 会保留重复键与顺序；逐个判定后重建，保证参数顺序稳定，
  // 非追踪参数（含重复键）原样保留，避免改变站点行为。
  const params = u.searchParams;
  for (const [key, value] of params) {
    const lk = key.toLowerCase();
    if (TRACKING_PARAMS.has(lk) || (hostParams && hostParams.has(lk))) {
      removed.push(lk);
    } else {
      kept.push([key, value]);
    }
  }

  if (removed.length === 0) {
    return { url: original, changed: false, removedKeys: [] };
  }

  const query = new URLSearchParams();
  for (const [k, v] of kept) {
    query.append(k, v);
  }
  const qs = query.toString();
  u.search = qs ? '?' + qs : '';
  const cleaned = u.toString();
  return { url: cleaned, changed: cleaned !== original, removedKeys: removed };
}

// unwrapRedirectTarget 尝试从已知“跳转包装”链接里解出真实目标。
// 目标必须仍是 http(s)；任何不匹配 / 缺参数 / 非法目标都原样返回。
function unwrapRedirectTarget(raw) {
  const original = String(raw || '');
  if (!isWebUrl(original)) {
    return { url: original, unwrapped: false };
  }
  let u;
  try {
    u = new URL(original);
  } catch {
    return { url: original, unwrapped: false };
  }

  const host = u.hostname.toLowerCase();
  for (const w of REDIRECT_WRAPPERS) {
    const hostMatch = host === w.suffix || host.endsWith('.' + w.suffix);
    if (!hostMatch) {
      continue;
    }
    if (w.pathIncludes && !u.pathname.toLowerCase().includes(w.pathIncludes)) {
      continue;
    }
    const inner = u.searchParams.get(w.param);
    if (!inner) {
      continue;
    }
    // Facebook 的目标可能是外层再编码一次。
    const decoded = safeDecode(inner);
    if (isWebUrl(decoded)) {
      return { url: decoded, unwrapped: true, wrapper: w.suffix };
    }
  }
  return { url: original, unwrapped: false };
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// cleanShareTarget 组合解包 + 清洗，用于“复制净化链接 / 收藏时去追踪”。
function cleanShareTarget(raw) {
  const step1 = unwrapRedirectTarget(raw);
  const step2 = cleanUrl(step1.url);
  return {
    url: step2.url,
    unwrapped: !!step1.unwrapped,
    changed: step2.changed || step1.unwrapped,
    removedKeys: step2.removedKeys,
  };
}

module.exports = {
  TRACKING_PARAMS,
  HOST_SPECIFIC_TRACKING,
  isWebUrl,
  cleanUrl,
  unwrapRedirectTarget,
  cleanShareTarget,
};
