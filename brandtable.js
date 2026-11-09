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

module.exports = {
  MULTI_PART_SUFFIX,
  SUSPICIOUS_WORDS,
  BRANDS,
  MIN_TYPO_LABEL_LEN,
  hostFromUrl,
  normalizeHost,
  registrableHost,
  registrableLabel,
};
