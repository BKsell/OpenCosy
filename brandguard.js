'use strict';

// brandguard.js —— 品牌仿冒 / 拼写劫持（typosquatting）检测的纯逻辑。
//
// 与 main.js 已有的“同形异义（homograph / IDN）”检测互补：
//   - homograph 盯的是“用别的文字/数字冒充拉丁字母”（如西里尔 а 冒充 a、0 冒充 o）；
//   - 本模块盯的是“纯拉丁域名里把品牌名拼错、蹭进子域、或塞安全词”的钓鱼套路：
//       paypa1.com      —— 数字/字母替换（注：纯拉丁数字替换部分由 homograph 覆盖，
//                          这里聚焦拼写编辑距离，避免重复提示）；
//       paypl.com / googe.com / amazom.com —— 与品牌仅一字之差（插入/删除/换位/替换）；
//       paypal.com.evil-login.xyz        —— 真品牌被放进子域，注册域其实是陌生站；
//       appleid-security-verify.com      —— 注册域里既含品牌词又含“安全/登录/验证”诱导词。
//
// 只“提示”不拦截：钓鱼识别有误伤空间，统一交给上层发横幅让用户自行核对。
//
// 隐私约束：与 requestlog 一致，只吃主机名、只吐主机名，永不接触路径/查询/Cookie；
// 纯函数、无 IO、无全局状态，便于 node --test 直接验证，且任何异常都不抛出到调用方。

// 常见多级后缀（eTLD 近似），与 requestlog 保持同一套，避免 co.uk 被截成 uk。
const MULTI_PART_SUFFIX = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.cn', 'net.cn', 'org.cn',
  'gov.cn', 'edu.cn', 'ac.cn', 'com.hk', 'com.tw', 'co.jp', 'co.kr',
  'com.au', 'com.br', 'co.in',
]);

// 出现在域名里、强烈暗示“想套你账号”的诱导词。单独出现不算钓鱼，
// 必须和某个品牌词同时出现在注册主体里才有意义。
const SUSPICIOUS_WORDS = [
  'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification',
  'secure', 'security', 'account', 'accounts', 'update', 'confirm',
  'billing', 'wallet', 'payments', 'support', 'help', 'restore',
  'recover', 'recovery', 'auth', 'sso', 'id', 'identifica',
];

// 品牌表：labels 是会被仿冒的核心拼写（小写、仅拉丁字母数字），
// official 是该品牌真正拥有的“注册域”（registrable host，不含子域）。
// 命中仿冒的前提永远是“注册域不在 official 白名单里”，从而保证官网零误伤。
const BRANDS = [
  {
    brand: 'paypal',
    labels: ['paypal'],
    official: ['paypal.com', 'paypal.co.uk', 'paypal.de', 'paypal.fr'],
  },
  {
    brand: 'apple',
    labels: ['apple', 'appleid', 'icloud'],
    official: ['apple.com', 'icloud.com', 'icloud-content.com', 'mzstatic.com'],
  },
  {
    brand: 'google',
    labels: ['google', 'gmail', 'gstatic'],
    official: [
      'google.com', 'google.co.uk', 'google.co.jp', 'gmail.com',
      'googlemail.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com',
    ],
  },
  {
    brand: 'microsoft',
    labels: ['microsoft', 'windows', 'office', 'live', 'outlook', 'hotmail'],
    official: [
      'microsoft.com', 'windows.com', 'office.com', 'live.com', 'office365.com',
      'outlook.com', 'hotmail.com', 'azure.com', 'microsoftonline.com', 'bing.com',
    ],
  },
  {
    brand: 'amazon',
    labels: ['amazon', 'amazonaws', 'primevideo'],
    official: [
      'amazon.com', 'amazon.co.uk', 'amazon.co.jp', 'amazonaws.com',
      'amazon.cn', 'primevideo.com',
    ],
  },
  {
    brand: 'github',
    labels: ['github', 'githubusercontent'],
    official: ['github.com', 'githubusercontent.com', 'githubassets.com', 'github.io'],
  },
  {
    brand: 'facebook',
    labels: ['facebook', 'messenger'],
    official: ['facebook.com', 'fb.com', 'messenger.com', 'meta.com'],
  },
  {
    brand: 'instagram',
    labels: ['instagram'],
    official: ['instagram.com', 'cdninstagram.com'],
  },
  {
    brand: 'netflix',
    labels: ['netflix', 'nflxvideo'],
    official: ['netflix.com', 'nflxvideo.net', 'nflxext.com'],
  },
  {
    brand: 'twitter',
    labels: ['twitter', 'x'],
    official: ['twitter.com', 'x.com', 'twimg.com'],
  },
  {
    brand: 'steam',
    labels: ['steam', 'steampowered', 'steamcommunity'],
    official: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'valvesoftware.com'],
  },
  {
    brand: 'epicgames',
    labels: ['epicgames', 'fortnite', 'unrealengine'],
    official: ['epicgames.com', 'fortnite.com', 'unrealengine.com', 'easyanticheat.net'],
  },
  {
    brand: 'alibaba',
    labels: ['alibaba', 'taobao', 'alipay', 'tmall'],
    official: [
      'alibaba.com', 'alicdn.com', 'taobao.com', 'tmall.com',
      'alipay.com', 'aliyun.com', 'alipayobjects.com',
    ],
  },
  {
    brand: 'tencent',
    labels: ['tencent', 'qq', 'wechat', 'weixin'],
    official: ['qq.com', 'tencent.com', 'weixin.qq.com', 'wechat.com', 'myqcloud.com'],
  },
  {
    brand: 'baidu',
    labels: ['baidu'],
    official: ['baidu.com', 'bdstatic.com', 'bdimg.com'],
  },
  {
    brand: 'binance',
    labels: ['binance'],
    official: ['binance.com', 'binance.us', 'bstatic.com'],
  },
  {
    brand: 'whatsapp',
    labels: ['whatsapp'],
    official: ['whatsapp.com', 'whatsapp.net'],
  },
  {
    brand: 'linkedin',
    labels: ['linkedin'],
    official: ['linkedin.com', 'licdn.com'],
  },
];

// 过短的品牌不做单字编辑距离判断（x/qq/id 之类只差一个字符的合法域名太多），
// 它们只走“子域碰瓷 / 品牌词+诱导词”两条更硬的规则。
const MIN_TYPO_LABEL_LEN = 5;

function hostFromUrl(rawUrl) {
  if (typeof rawUrl !== 'string') return '';
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return '';
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
  return normalizeHost(u.hostname);
}

function normalizeHost(hostname) {
  return String(hostname || '').toLowerCase().replace(/\.$/, '').trim();
}

// registrableHost 返回近似的 eTLD+1（如 www.paypal.com -> paypal.com，
// news.bbc.co.uk -> bbc.co.uk）。
function registrableHost(hostname) {
  const h = normalizeHost(hostname);
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return h;
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIX.has(last2) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return last2;
}

// registrableLabel 取注册主体的核心标签：paypal.com -> paypal，
// bbc.co.uk -> bbc。用于和品牌拼写做编辑距离比较。
function registrableLabel(hostname) {
  const reg = registrableHost(hostname);
  const parts = reg.split('.').filter(Boolean);
  return parts.length ? parts[0] : '';
}

// levenshtein 计算 Damerau–Levenshtein 距离（把相邻两字符换位也算 1 步），
// 命中阈值可提前剪枝。钓鱼者常把 goog|le 注册成 gool|ge，普通编辑距离会算成 2，
// 相邻换位计 1 才能识别这类“敲错一个键”的域名。
function levenshtein(a, b, max) {
  const cap = Number.isInteger(max) ? max : Infinity;
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  const m = a.length;
  const n = b.length;
  let prevPrev = null; // i-2 行
  let prev = new Array(n + 1);
  let cur = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= n; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      // 相邻字符换位：ab <-> ba
      if (i > 1 && j > 1 && prevPrev &&
          a.charCodeAt(i - 1) === b.charCodeAt(j - 2) &&
          a.charCodeAt(i - 2) === b.charCodeAt(j - 1)) {
        cur[j] = Math.min(cur[j], prevPrev[j - 2] + 1);
      }
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > cap) return cap + 1;
    prevPrev = prev;
    prev = cur;
    cur = new Array(n + 1);
  }
  return prev[n];
}

// isOfficialDomain 判断注册域是否属于该品牌官方域。
function isOfficialDomain(reg, brandDef) {
  return brandDef.official.includes(reg);
}

// findBrandByToken 在品牌表里找“核心标签正好等于 token”的品牌；找不到返回 null。
function findBrandByToken(token) {
  for (const def of BRANDS) {
    if (def.labels.includes(token)) return def;
  }
  return null;
}

// containsSuspiciousWord 判断注册主体里是否含诱导词。先按非字母数字切词后精确匹配
// （命中短词 id/sso/auth 等也安全）；再对长度 >=5 的诱导词做一次 includes 兜底，
// 抓住 "appleidverify" 这种无分隔符的连写（短词不做子串匹配，避免 rapid/idea 误伤）。
function containsSuspiciousWord(label) {
  const tokens = label.split(/[^a-z0-9]+/).filter(Boolean);
  if (tokens.some(t => SUSPICIOUS_WORDS.includes(t))) return true;
  return SUSPICIOUS_WORDS.some(w => w.length >= 5 && label.includes(w));
}

// analyzeBrand 是主入口：给主机名，返回仿冒结论或 null。结论形状与
// homograph 检测对齐：{ reason, hostname, brand, hint }。纯函数，不抛错。
function analyzeBrand(rawHostname) {
  let hostname;
  try {
    hostname = normalizeHost(rawHostname);
  } catch {
    return null;
  }
  if (!hostname || !hostname.includes('.') || /[^\x21-\x7e]/.test(hostname)) return null; // 非 ASCII 交给 homograph

  const reg = registrableHost(hostname);
  const regLabel = registrableLabel(hostname);
  if (!reg || !regLabel) return null;

  // 规则 1：注册主体与某品牌拼写只差 1 个编辑操作，却不在官方域里 → 拼写劫持。
  if (regLabel.length >= MIN_TYPO_LABEL_LEN) {
    for (const def of BRANDS) {
      if (isOfficialDomain(reg, def)) continue;
      for (const label of def.labels) {
        if (label.length < MIN_TYPO_LABEL_LEN) continue;
        if (Math.abs(label.length - regLabel.length) > 1) continue;
        const d = levenshtein(label, regLabel, 1);
        if (d === 1) {
          return { reason: 'typo-domain', hostname, brand: def.brand, hint: label };
        }
      }
    }
  }

  // 规则 2：品牌词出现在注册域“左侧”的子域里，而注册域本身不是官方站。
  // 例：paypal.com.evil.xyz、login.microsoft.account-verify.net 的注册域是陌生站。
  const regPrefix = hostname.slice(0, hostname.length - reg.length);
  if (regPrefix) {
    const leftLabels = regPrefix.replace(/\.$/, '').split('.').filter(Boolean);
    for (const lbl of leftLabels) {
      const compact = lbl.replace(/[^a-z0-9]/g, '');
      const def = findBrandByToken(compact) || findBrandByToken(lbl);
      if (def && !isOfficialDomain(reg, def)) {
        return { reason: 'brand-in-subdomain', hostname, brand: def.brand, hint: reg };
      }
    }
  }

  // 规则 3：注册主体里同时含品牌词与“登录/验证/安全”等诱导词，且非官方域。
  // 例：appleid-security-verify.com、paypal-account-update.org。
  if (containsSuspiciousWord(regLabel)) {
    for (const def of BRANDS) {
      if (isOfficialDomain(reg, def)) continue;
      for (const label of def.labels) {
        if (label.length < 4) continue;
        if (regLabel.includes(label)) {
          return { reason: 'brand-keyword-impersonation', hostname, brand: def.brand, hint: label };
        }
      }
    }
  }

  return null;
}

module.exports = {
  BRANDS,
  SUSPICIOUS_WORDS,
  MIN_TYPO_LABEL_LEN,
  hostFromUrl,
  normalizeHost,
  registrableHost,
  registrableLabel,
  levenshtein,
  isOfficialDomain,
  containsSuspiciousWord,
  analyzeBrand,
};
