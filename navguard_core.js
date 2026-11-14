'use strict';

const { CYRILLIC_LOOKALIKES, GREEK_LOOKALIKES, DIGIT_LOOKALIKES, scriptOfCodePoint, countScripts, mapToLatinLookalike, decodePunyLabel } = require('./navguardlookalike_core');

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

const RISK_OK = 'allow';
const RISK_WARN = 'warn';
const RISK_BLOCK = 'block';

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
