
const { MULTI_PART_SUFFIX, SUSPICIOUS_WORDS, BRANDS, MIN_TYPO_LABEL_LEN, hostFromUrl, normalizeHost, registrableHost, registrableLabel } = require('./brandtable');
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
