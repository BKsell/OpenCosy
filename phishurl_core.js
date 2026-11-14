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
const { mapToLatinLookalike, decodePunyLabel } = require('./navguard_core');
const { isIPv4Literal, extractRawHost, hostHasPercentEncoding, foldCompat, tldOf, registrableLabel, leftLabels, isLikelyMainstreamHost, decodeURIComponentSafe } = require('./phishhost_core');

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
  homoglyphBrand: 40,
  suspiciousTldWithBrand: 25,
  unusualPortWithBrand: 15,
  deepSubdomainWithBrand: 15,
  hyphenStackWithBrand: 15,
  brandInPathOnForeignHost: 20,
  decimalHexIp: 20,
  compatFoldedHost: 35,
};
const HIGH_SCORE = 40;
const MEDIUM_SCORE = 20;

function foldLookalikeHost(hostname) {
  const out = [];
  for (const rawLabel of String(hostname || '').split('.')) {
    if (!rawLabel) continue;
    const label = rawLabel.startsWith('xn--') ? (decodePunyLabel(rawLabel) || rawLabel) : rawLabel;
    const cand = mapToLatinLookalike(label);
    if (cand && cand.ok) out.push(cand.mapped);
  }
  return out.join('.');
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
  const hostFold = foldCompat(rawHost);
  const lookalikeFold = foldLookalikeHost(hostname);
  const brandInLookalike = lookalikeFold ? findBrandToken(lookalikeFold) : null;

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
  const brandOnHost = findBrandToken(hostFold);
  const brandAnywhere = brandInUserinfo || brandOnLeft || brandInRegistrable || brandInPath || brandOnHost || brandInLookalike;

  // 1) userinfo：http://paypal.com@evil.com 是最经典的地址栏障眼法。
  if (userinfo || u.password) {
    add('userinfo', 'URL 的 @ 左侧带账号信息，实际打开的是 @ 右侧主机');
    if (brandInUserinfo) add('brandInUserinfo', '品牌词出现在 @ 左侧：' + brandInUserinfo);
  }

  // 2) 主机里出现百分号编码（%2e 点、%2f 斜杠等），典型的绕过检查手法。
  if (hostHasPercentEncoding(rawHost)) {
    add('encodedHost', '主机名含百分号编码字符');
  }

  if (hostFold !== rawHost.toLowerCase()) {
    add('compatFoldedHost', '主机含全角/兼容字符，NFKC 归一化后才等价于 ' + hostFold);
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

  if (lookalikeFold && brandInLookalike) {
    add('homoglyphBrand', '同形异义字主机折叠成拉丁后暴露品牌词：' + lookalikeFold);
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
  // 强信号排前面，渲染层直接按顺序展示即可。
  signals.sort((x, y) => y.weight - x.weight);
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
