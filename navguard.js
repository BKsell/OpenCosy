'use strict';

// navguard.js —— 顶层导航安全内核：IDN 同形异义字（homograph）钓鱼 +
// HTTPS → HTTP 降级导航。纯判定逻辑，不接触 Electron，便于 node:test。
//
// 威胁模型：
//   1) 同形异义字钓鱼：攻击者用西里尔/希腊字母里长得和拉丁字母一模一样的字符
//      注册“раypal.com”“gοogle.com”（肉眼几乎无法分辨），或混用多脚本、塞
//      Punycode（xn--）伪装成正规域名。浏览器地址栏虽会对部分 IDN 降级显示
//      Punycode，但并非所有混淆形态都会拦。
//   2) 安全降级：用户在 https 页面里被顶层导航带到 http:// 同名/仿冒站，凭据
//      与 Cookie 在明文链路上泄露（SSL stripping / 登录降级）。
//
// 本内核输出 allow / warn / block 三档决策与原因链，由主进程 will-navigate /
// did-start-navigation 调用：block 直接拦截，warn 弹原生间隙页让用户确认。

// 仅在 Node 环境取 domainToUnicode；浏览器/缺省环境下降级为“不解码”。
let domainToUnicode = null;
try {
  // eslint-disable-next-line global-require
  const nodeUrl = require('url');
  if (typeof nodeUrl.domainToUnicode === 'function') {
    domainToUnicode = nodeUrl.domainToUnicode;
  }
} catch { domainToUnicode = null; }

const RISK_OK = 'allow';
const RISK_WARN = 'warn';
const RISK_BLOCK = 'block';

// 西里尔字母 → 视觉等价拉丁字母（只收录高置信的同形字，用码位显式列出）。
const CYRILLIC_LOOKALIKES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  'ь': 'b', 'ѕ': 's', 'і': 'i', 'ј': 'j',
  'ԁ': 'd', 'ԓ': 'l', 'ԛ': 'q', 'ԝ': 'w',
};

// 希腊字母 → 视觉等价拉丁字母（码位显式列出，避免肉眼重复）。
const GREEK_LOOKALIKES = {
  'ο': 'o', 'ε': 'e', 'α': 'a', 'ρ': 'p', 'ν': 'v', 'ι': 'i',
  'κ': 'k', 'μ': 'm', 'τ': 't', 'χ': 'x', 'υ': 'y',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I',
  'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T',
  'Υ': 'Y', 'Χ': 'X',
};

// 数字 / 符号 → 易混字母（用于无分隔连写标签的弱信号）。
const DIGIT_LOOKALIKES = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
};

function isAsciiLetter(ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}
function isAsciiDigit(ch) {
  return ch >= '0' && ch <= '9';
}

// scriptOfCodePoint 粗分类单个字符所属脚本族。
function scriptOfCodePoint(cp) {
  if ((cp >= 0x0041 && cp <= 0x005A) || (cp >= 0x0061 && cp <= 0x007A)) return 'Latin';
  if (cp >= 0x0030 && cp <= 0x0039) return 'Digit';
  if (cp === 0x002D || cp === 0x002E) return 'Common'; // - .
  if (cp >= 0x0400 && cp <= 0x04FF) return 'Cyrillic';
  if (cp >= 0x0500 && cp <= 0x052F) return 'Cyrillic'; // 西里尔扩展
  if (cp >= 0x1C80 && cp <= 0x1C8F) return 'Cyrillic';
  if (cp >= 0x0370 && cp <= 0x03FF) return 'Greek';
  if (cp >= 0x1F00 && cp <= 0x1FFF) return 'Greek';
  return 'Other';
}

// countScripts 统计一个标签里出现的“有意义”脚本族（拉丁/西里尔/希腊）。
function countScripts(label) {
  const scripts = new Set();
  for (const ch of label) {
    const s = scriptOfCodePoint(ch.codePointAt(0));
    if (s === 'Latin' || s === 'Cyrillic' || s === 'Greek') scripts.add(s);
  }
  return scripts;
}

// mapToLatinLookalike 尝试把整标签映射成纯拉丁串。
// 返回 { mapped, changed }：只有当每个非 ASCII 字母都能映射、且结果仍像
// 域名标签（[A-Za-z0-9-]）时才算成功的同形候选。
function mapToLatinLookalike(label) {
  let mapped = '';
  let changed = false;
  for (const ch of label) {
    if (isAsciiLetter(ch) || isAsciiDigit(ch) || ch === '-') {
      mapped += ch;
    } else if (Object.prototype.hasOwnProperty.call(CYRILLIC_LOOKALIKES, ch)) {
      mapped += CYRILLIC_LOOKALIKES[ch];
      changed = true;
    } else if (Object.prototype.hasOwnProperty.call(GREEK_LOOKALIKES, ch)) {
      mapped += GREEK_LOOKALIKES[ch];
      changed = true;
    } else {
      return { mapped: '', changed: false, ok: false };
    }
  }
  return { mapped, changed, ok: changed && /^[A-Za-z0-9-]+$/.test(mapped) };
}

// decodePunyLabel 把单个 xn-- 标签解码成 Unicode；失败返回空串。
function decodePunyLabel(label) {
  if (!label || label.toLowerCase().indexOf('xn--') !== 0) return '';
  if (domainToUnicode) {
    try {
      const u = domainToUnicode(label);
      return u && u !== label ? u : '';
    } catch { return ''; }
  }
  return '';
}

// splitLabels 切主机名为小写标签数组（去尾点）。
function splitLabels(host) {
  return String(host || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
}

// analyzeHostname 对主机名做同形异义字分析。
// 返回 { risk, reasons, punycode, mixedScript, lookalikes:[{label,mapped}] }。
function analyzeHostname(rawHost) {
  const host = String(rawHost || '');
  const result = { risk: RISK_OK, reasons: [], punycode: false, mixedScript: false, lookalikes: [] };
  if (!host) return result;

  const labels = splitLabels(host);
  for (const originalLabel of labels) {
    let label = originalLabel;

    // Punycode：先尝试解码看真实字符；无论如何都标记（xn-- 本身就是弱信号）。
    if (originalLabel.indexOf('xn--') === 0) {
      result.punycode = true;
      const decoded = decodePunyLabel(originalLabel);
      if (decoded) label = decoded;
      result.reasons.push('punycode-label:' + originalLabel);
    }

    const scripts = countScripts(label);
    // 同一标签里混用拉丁 + 西里尔/希腊 → 高置信钓鱼，直接 block。
    if (scripts.has('Latin') && (scripts.has('Cyrillic') || scripts.has('Greek'))) {
      result.mixedScript = true;
      result.reasons.push('mixed-script-label:' + label);
      result.risk = RISK_BLOCK;
    }

    // 非拉丁脚本能完整映射成拉丁串 → 同形品牌候选（整词替换），warn。
    if (!scripts.has('Latin') && (scripts.has('Cyrillic') || scripts.has('Greek'))) {
      const cand = mapToLatinLookalike(label);
      if (cand.ok) {
        result.lookalikes.push({ label, mapped: cand.mapped });
        result.reasons.push('whole-label-lookalike:' + label + '->' + cand.mapped);
        if (result.risk !== RISK_BLOCK) result.risk = RISK_WARN;
      }
    }
  }

  // 出现 xn-- 但未坐实更强信号时，至少给 warn（提示正在访问编码域名）。
  if (result.punycode && result.risk === RISK_OK) result.risk = RISK_WARN;
  return result;
}

// isHttps / isHttp 判定 URL 协议。
function schemeIs(rawUrl, proto) {
  const m = /^([a-z][a-z0-9+.-]*):/i.exec(String(rawUrl || '').trim());
  return !!m && m[1].toLowerCase() === proto;
}

// hostnameOf 安全取小写主机名，失败返回空串。
function hostnameOf(rawUrl) {
  try { return new URL(rawUrl).hostname.toLowerCase(); } catch { return ''; }
}

// isDowngradeNavigation 判定从安全页顶层跳到明文 http。
// 返回 { downgrade, sameHost, fromHost, toHost }。
function isDowngradeNavigation(currentUrl, targetUrl) {
  const out = { downgrade: false, sameHost: false, fromHost: '', toHost: '' };
  if (!currentUrl || !targetUrl) return out;
  if (!schemeIs(currentUrl, 'https') || !schemeIs(targetUrl, 'http')) return out;
  out.downgrade = true;
  out.fromHost = hostnameOf(currentUrl);
  out.toHost = hostnameOf(targetUrl);
  out.sameHost = !!out.fromHost && out.fromHost === out.toHost;
  return out;
}

// decideNavigation 是主进程导航守卫的统一入口。
// 入参 { currentUrl, targetUrl }。
// 返回 { action:'allow'|'warn'|'block', reasons:{ host:[], nav:[] }, host }。
function decideNavigation(input) {
  const opts = input || {};
  const targetUrl = typeof opts.targetUrl === 'string' ? opts.targetUrl : '';
  const currentUrl = typeof opts.currentUrl === 'string' ? opts.currentUrl : '';
  const reasons = { host: [], nav: [] };
  let action = RISK_OK;

  const raise = (level, bucket, reason) => {
    reasons[bucket].push(reason);
    if (level === RISK_BLOCK) action = RISK_BLOCK;
    else if (level === RISK_WARN && action !== RISK_BLOCK) action = RISK_WARN;
  };

  // 1) 主机名同形异义字 / Punycode。
  const host = hostnameOf(targetUrl);
  if (host) {
    const ana = analyzeHostname(host);
    if (ana.risk === RISK_BLOCK) {
      for (const r of ana.reasons) raise(RISK_BLOCK, 'host', r);
    } else if (ana.risk === RISK_WARN) {
      for (const r of ana.reasons) raise(RISK_WARN, 'host', r);
    }
  }

  // 2) https → http 降级。跨主机降级直接拦；同主机降级警告（可能是站点自身
  //    配置问题，强拦会误伤），交用户确认。
  const dg = isDowngradeNavigation(currentUrl, targetUrl);
  if (dg.downgrade) {
    if (dg.sameHost) {
      raise(RISK_WARN, 'nav', 'https-to-http-same-host');
    } else {
      raise(RISK_BLOCK, 'nav', 'https-to-http-cross-host');
    }
  }

  return { action, reasons, host, downgrade: dg };
}

module.exports = {
  RISK_OK,
  RISK_WARN,
  RISK_BLOCK,
  CYRILLIC_LOOKALIKES,
  GREEK_LOOKALIKES,
  DIGIT_LOOKALIKES,
  scriptOfCodePoint,
  countScripts,
  mapToLatinLookalike,
  decodePunyLabel,
  analyzeHostname,
  isDowngradeNavigation,
  hostnameOf,
  decideNavigation,
};
