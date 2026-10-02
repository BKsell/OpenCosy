'use strict';

// phishurl.js —— 钓鱼 URL 结构特征检测的纯逻辑。
//
// brandguard 盯“品牌名拼错/蹭子域”，homograph 盯“用别的文字冒充拉丁字母”。
// 本模块盯的是第三类套路：URL 结构本身就在玩花招——
//   http://paypal.com@evil.com/        用 userinfo 把真品牌写到 @ 左边，
//                                      实际打开的是 @ 右边的 evil.com；
//   http://192.168.90.11/paypal        用裸 IP 冒充官网，没有正常域名；
//   http://0x7f.0.0.1/                 十六进制/八进制 IP，地址栏一眼看不出是内网；
//   https://paypal.com.secure-login.xyz:8443/  品牌进子域 + 非标端口；
//   http://xn--pypal-xxx/login         punycode 主机 + 路径里带品牌词；
//   https://appple-login-verification.xyz/     可疑廉价 TLD + 一堆连字符。
//
// 输出是“加权打分 + 命中信号列表”，调用方（main 进程顶层导航）按分数决定是否发横幅。
// 只做提示不拦截，且所有强信号都要求“出现品牌词”或“结构本身就危险（userinfo/
// 编码主机/裸 IP）”，从而把对普通网站的误伤压到最低。
//
// 隐私约束：只解析 URL 结构，不记录查询值、Cookie、请求体；纯函数、无 IO、不抛错。

// 会被钓鱼者高频蹭的品牌核心词（小写）。与 brandguard 各有一份：
// 本模块只需要“有没有出现品牌词”这一布尔判断，不做编辑距离，单独列更清晰。
const BRAND_TOKENS = [
  'paypal', 'apple', 'appleid', 'icloud', 'google', 'gmail', 'microsoft',
  'windows', 'office', 'live', 'outlook', 'hotmail', 'amazon', 'aws',
  'github', 'facebook', 'instagram', 'netflix', 'twitter', 'linkedin',
  'whatsapp', 'steam', 'steampowered', 'epicgames', 'fortnite', 'alibaba',
  'taobao', 'alipay', 'tmall', 'tencent', 'qq', 'wechat', 'weixin',
  'baidu', 'binance', 'coinbase', 'metamask', 'uber', 'ebay',
];

// 廉价 / 易被滥用、常出现在钓鱼跳转里的后缀。单独出现不算钓鱼，
// 必须再叠加“含品牌词”这一条件。
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'click', 'country', 'zip', 'mov', 'gq', 'tk', 'ml',
  'ga', 'cf', 'work', 'fit', 'gdn', 'kim', 'loan', 'men', 'review',
  'trade', 'stream', 'support', 'biz', 'info',
]);

// 现代网页正常使用的端口；出现在其他端口本身只是弱信号。
const COMMON_WEB_PORTS = new Set([80, 443, 8080, 8443]);

// 各级权重与阈值。分数 >= HIGH_SCORE 发强提示。
const WEIGHTS = {
  userinfo: 45,
  encodedHost: 45,
  bareIPv4: 45,
  brandInUserinfo: 25,
  punycodeWithBrand: 40,
  suspiciousTldWithBrand: 25,
  unusualPortWithBrand: 15,
  deepSubdomainWithBrand: 15,
  hyphenStackWithBrand: 15,
  brandInPathOnForeignHost: 20,
  decimalHexIp: 20,
};
const HIGH_SCORE = 40;
const MEDIUM_SCORE = 20;

function decodePunyHost(hostname) {
  // 只判断“有没有 xn-- 标签”，不真正做 IDNA 转换（Chromium 已处理显示）。
  return hostname;
}

// isIPv4Literal 判断主机是否是裸 IPv4，支持点分十进制、十六进制（0x..）、
// 八进制（前导 0）这类 Node/URL 不会归一化、但部分系统仍会解析的写法。
function isIPv4Literal(host) {
  const h = String(host || '').toLowerCase();
  if (!h) return null;
  // 标准点分十进制
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) {
    const parts = h.split('.').map(Number);
    if (parts.every(n => n >= 0 && n <= 255)) return 'ipv4';
  }
  // 每段为十进制 / 0x 十六进制 / 前导 0 八进制之一
  if (/^(?:0x[0-9a-f]+|0[0-7]+|\d{1,3})(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d{1,3})){3}$/.test(h)) {
    return 'ipv4-nondecimal';
  }
  // 单个整数 / 0x 整数形式（http://2130706433）
  if (/^(?:0x[0-9a-f]+|\d{8,10})$/.test(h)) return 'ipv4-flat';
  // [::1] 这类 IPv6 字面量
  if (/^\[[0-9a-f:]+\]$/i.test(h)) return 'ipv6';
  return null;
}

// extractRawHost 从原始 URL 串切出未规范化的主机（去掉协议、userinfo、
// 端口、路径）。只用于检测“非十进制 IP / 百分号编码”这类会被 WHATWG URL
// 规范化掉的写法；结构判断仍以 new URL 的 hostname 为准。
function extractRawHost(rawUrl) {
  let s = String(rawUrl || '');
  const m = s.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//);
  if (!m) return '';
  s = s.slice(m[0].length);
  // 去掉 userinfo（@ 左侧全部内容，取最后一个 @ 之后）。
  const at = s.lastIndexOf('@');
  if (at >= 0) s = s.slice(at + 1);
  // 截到路径 / 查询 / 片段。
  s = s.split(/[/?#]/)[0] || '';
  // 去端口。
  s = s.replace(/:\d+$/, '');
  return s.toLowerCase();
}

// hostHasPercentEncoding 主机里若出现 %2e/%2f 之类编码，基本就是在躲地址栏检查。
function hostHasPercentEncoding(hostname) {
  return /%[0-9a-fA-F]{2}/.test(hostname);
}

function tokenize(text) {
  return String(text || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

// findBrandToken 在一段文本的切词结果里找品牌词；返回命中的词，否则 null。
function findBrandToken(text) {
  const tokens = tokenize(text);
  const compact = String(text || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const b of BRAND_TOKENS) {
    if (tokens.includes(b)) return b;
  }
  for (const b of BRAND_TOKENS) {
    if (b.length >= 5 && compact.includes(b)) return b;
  }
  return null;
}

function tldOf(hostname) {
  const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
  return parts.length ? parts[parts.length - 1] : '';
}

// analyze 是主入口。给 URL 字符串，返回
//   null（无风险）或
//   { url, hostname, score, level, brand, signals: [{code,weight,detail}] }
// 纯函数，任何异常都吞掉返回 null，绝不影响导航主流程。
function analyze(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

  const hostname = (u.hostname || '').toLowerCase();
  if (!hostname) return null;

  // WHATWG URL 会把 0x7f.0.0.1、0177.0.0.1 这类非十进制 IP 规范化成 127.0.0.1，
  // 从而丢掉“用怪写法躲检查”这个信号。因此 IP / 编码检测改用从原始串里切出的
  // 原始主机，子域/注册域等结构判断仍用规范化后的 hostname。
  const rawHost = extractRawHost(rawUrl);

  const signals = [];
  const add = (code, detail) => {
    const weight = WEIGHTS[code];
    if (weight) signals.push({ code, weight, detail: String(detail || '').slice(0, 120) });
  };

  // 主机之外可能露出品牌词的位置：@ 左侧 userinfo、路径、左侧子域，
  // 以及注册主体自身（paypal-secure.xyz 这种把品牌做进注册名的）。
  const userinfo = u.username ? decodeURIComponentSafe(u.username) : '';
  const left = leftLabels(hostname);
  const regLabel = registrableLabel(hostname);
  const leftOfRegistrable = left.join('.');
  const pathText = u.pathname;

  const brandInUserinfo = findBrandToken(userinfo);
  const brandOnLeft = findBrandToken(leftOfRegistrable);
  const brandInRegistrable = findBrandToken(regLabel);
  const brandInPath = findBrandToken(pathText);
  const brandAnywhere = brandInUserinfo || brandOnLeft || brandInRegistrable || brandInPath;

  // 1) userinfo：http://paypal.com@evil.com 是最经典的地址栏障眼法。
  if (userinfo || u.password) {
    add('userinfo', 'URL 的 @ 左侧带账号信息，实际打开的是 @ 右侧主机');
    if (brandInUserinfo) add('brandInUserinfo', '品牌词出现在 @ 左侧：' + brandInUserinfo);
  }

  // 2) 主机里出现百分号编码（%2e 点、%2f 斜杠等），典型的绕过检查手法。
  if (hostHasPercentEncoding(rawHost)) {
    add('encodedHost', '主机名含百分号编码字符');
  }

  // 3) 裸 IP 主机：正规品牌官网几乎不会让你在 IP 上登录。
  const ipKind = isIPv4Literal(rawHost.replace(/^\[|\]$/g, ''));
  if (ipKind === 'ipv4' || ipKind === 'ipv6') {
    add('bareIPv4', '主机是裸 IP 地址而非常见域名');
  } else if (ipKind === 'ipv4-nondecimal' || ipKind === 'ipv4-flat') {
    add('bareIPv4', '主机是非标准写法的 IP 地址');
    add('decimalHexIp', '十六进制/八进制/扁平整数 IP，地址栏难以辨认');
  }

  // 4) punycode（xn--）主机，同时品牌词出现在左侧子域或路径里 → IDN 钓鱼。
  const hasPuny = hostname.split('.').some(l => l.startsWith('xn--'));
  if (hasPuny && brandAnywhere) {
    add('punycodeWithBrand', 'punycode 国际域名叠加品牌词：' + brandAnywhere);
  }

  // 5) 可疑廉价 TLD + 品牌词。
  const tld = tldOf(hostname);
  if (SUSPICIOUS_TLDS.has(tld) && brandAnywhere) {
    add('suspiciousTldWithBrand', '高风险后缀 .' + tld + ' 叠加品牌词：' + brandAnywhere);
  }

  // 6) 非通用 Web 端口 + 品牌词。
  const port = Number(u.port || 0);
  if (port && !COMMON_WEB_PORTS.has(port) && brandAnywhere) {
    add('unusualPortWithBrand', '非标端口 ' + port + ' 叠加品牌词');
  }

  // 7) 子域嵌套过深（>=4 个左标签）+ 品牌词。
  if (leftLabels(hostname).length >= 4 && brandAnywhere) {
    add('deepSubdomainWithBrand', '子域层级过深并夹带品牌词：' + brandAnywhere);
  }

  // 8) 注册主体里连字符堆叠（>=3）+ 品牌词。
  const hyphens = (regLabel.match(/-/g) || []).length;
  if (hyphens >= 3 && findBrandToken(regLabel)) {
    add('hyphenStackWithBrand', '注册名堆叠 ' + hyphens + ' 个连字符并含品牌词');
  }

  // 9) 路径里带品牌词，但注册主机既不常见、也不是官方域（弱信号，
  //    交给分数叠加，不单独误报）。
  if (brandInPath && !brandOnLeft && !brandInUserinfo &&
      !isLikelyMainstreamHost(hostname) && (SUSPICIOUS_TLDS.has(tld) || ipKind || hasPuny)) {
    add('brandInPathOnForeignHost', '路径含品牌词 ' + brandInPath + ' 但主机陌生');
  }

  if (!signals.length) return null;
  const score = signals.reduce((sum, s) => sum + s.weight, 0);

  return {
    url: String(rawUrl).slice(0, 2048),
    hostname,
    score,
    level: score >= HIGH_SCORE ? 'high' : score >= MEDIUM_SCORE ? 'medium' : 'low',
    brand: brandAnywhere || '',
    signals,
  };
}

// leftLabels 返回注册域左侧的子域标签数组（a.b.paypal.com -> [a,b]，
// 对 co.uk 这类多级后缀取三段）。纯启发式，与 brandguard 的近似保持一致。
const MULTI_PART_SUFFIX = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.cn', 'net.cn', 'org.cn',
  'gov.cn', 'edu.cn', 'ac.cn', 'com.hk', 'com.tw', 'co.jp', 'co.kr',
  'com.au', 'com.br', 'co.in',
]);

function registrableLabel(hostname) {
  const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts[0] || '';
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIX.has(last2) && parts.length >= 3) return parts[parts.length - 3];
  return parts[parts.length - 2];
}

function leftLabels(hostname) {
  const h = String(hostname || '').toLowerCase();
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return [];
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIX.has(last2) && parts.length >= 3) return parts.slice(0, -3);
  return parts.slice(0, -2);
}

// isLikelyMainstreamHost 对明显的大型托管/CDN 域名降权，避免“陌生主机”判断过宽。
const MAINSTREAM_HINTS = [
  'amazonaws.com', 'cloudfront.net', 'azureedge.net', 'akamaihd.net',
  'googleusercontent.com', 'github.io', 'vercel.app', 'netlify.app',
  'cloudflare.com', 'workers.dev', 'azurewebsites.net', 'herokuapp.com',
];
function isLikelyMainstreamHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  return MAINSTREAM_HINTS.some(suffix => h === suffix || h.endsWith('.' + suffix));
}

function decodeURIComponentSafe(s) {
  try { return decodeURIComponent(s); } catch { return String(s || ''); }
}

module.exports = {
  BRAND_TOKENS,
  SUSPICIOUS_TLDS,
  WEIGHTS,
  HIGH_SCORE,
  MEDIUM_SCORE,
  isIPv4Literal,
  hostHasPercentEncoding,
  extractRawHost,
  findBrandToken,
  registrableLabel,
  leftLabels,
  isLikelyMainstreamHost,
  analyze,
};
