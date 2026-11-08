'use strict';

// preloadpolicy.js —— preload 暴露面（attack surface）策略内核。
//
// 威胁模型：
//   OpenCosy 同时存在两类渲染上下文，但它们历史上共用同一份“全功能” preload.js：
//     1) 内部受信 UI：主窗口外壳（file: 的 src/index.html）与标签承载的内置页
//        （cosy://newtab、cosy://security、错误页等），这些页面是浏览器自己的代码，
//        需要完整的 electronAPI（标签、设置、下载、安全面板……）；
//     2) 任意远程网页：用户浏览的 http(s) 站点，以及 data:/blob:/about: 等不可信
//        文档，它们跑在独立的 WebContentsView 里，却因为同一份 preload 而同样拿到
//        了 electronAPI 上约 130 个 invoke/send 通道。任何一个被访问的恶意站点都能
//        直接调用“清除浏览数据 / 导出配置 / 放行证书例外”等特权方法（主进程的逐
//        handler 兜底一旦遗漏就是越权）。
//
//   本模块只负责一个纯判定：给定当前文档地址，决定它属于“内部受信上下文”还是
//   “不可信远程上下文”。preload 据此决定是否注入完整 API：远程上下文一律不注入
//   任何业务 IPC（连 send/invoke/on 入口都不给），从渲染侧先削掉整个攻击面；
//   主进程另有 ipcguard 按帧来源做第二道兜底，二者纵深、互不替代。
//
//   设计约束：sandbox preload 里不能依赖 Node 的 url 模块，这里只做基于字符串的
//   保守协议解析，不做任何可能被畸形 URL 骗过的“关键字包含”判断。

// 允许拿到完整 electronAPI 的内部协议（小写、带冒号）。
//   file: —— 打包在应用内、由主窗口 loadFile 加载的外壳页面；
//   cosy: —— 浏览器注册的内置 scheme（新标签页 / 安全面板 / 内置错误页）。
const INTERNAL_PROTOCOLS = new Set(['file:', 'cosy:']);

// 明确归类为“远程网页”的协议。
const WEB_PROTOCOLS = new Set(['http:', 'https:']);

// 其余一切协议（data: / blob: / about: / javascript: / vbscript: / 未知 scheme）
// 都按不可信处理：宁可不给 API，也不赌它无害。

const ORIGIN_SHELL_FILE = 'shell-file';   // file: 文档（preload 无法区分主窗口/标签文件）
const ORIGIN_INTERNAL_COSY = 'cosy';      // cosy: 内置页
const ORIGIN_WEB = 'web';                 // http/https 远程网页
const ORIGIN_UNTRUSTED = 'untrusted';     // data/blob/about/其它未知 scheme
const ORIGIN_UNKNOWN = 'unknown';         // 连地址都拿不到

/**
 * 从文档地址中取出小写的协议（含结尾冒号）。解析失败或无协议时返回空串。
 * 不做 trim 之外的宽容处理，避免 " https://" 之类被误判。
 * @param {string} rawUrl
 * @returns {string}
 */
function parseProtocol(rawUrl) {
  if (typeof rawUrl !== 'string') return '';
  const s = rawUrl.trim();
  if (s === '') return '';
  const colon = s.indexOf(':');
  if (colon <= 0) return '';
  const head = s.slice(0, colon);
  // 协议只能由 ASCII 字母组成（scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )），
  // 第一个字符必须是字母；含空白 / 分隔符的直接判非法。
  if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*$/.test(head)) return '';
  return head.toLowerCase() + ':';
}

/**
 * 判定文档地址是否属于“内部受信上下文”。这是 preload 是否注入完整 API 的唯一依据，
 * 必须保持保守：只有 file:/cosy: 为真，其它一切（含拿不到地址）都为假。
 * @param {string} rawUrl
 * @returns {boolean}
 */
function isInternalContext(rawUrl) {
  return INTERNAL_PROTOCOLS.has(parseProtocol(rawUrl));
}

/**
 * 给出文档地址的来源分类，便于日志与测试精确断言，而不是一个布尔值包打天下。
 * @param {string} rawUrl
 * @returns {string}
 */
function classifyLocation(rawUrl) {
  const proto = parseProtocol(rawUrl);
  if (proto === '') {
    return rawUrl === undefined || rawUrl === null || (typeof rawUrl === 'string' && rawUrl.trim() === '')
      ? ORIGIN_UNKNOWN
      : ORIGIN_UNTRUSTED;
  }
  if (proto === 'file:') return ORIGIN_SHELL_FILE;
  if (proto === 'cosy:') return ORIGIN_INTERNAL_COSY;
  if (WEB_PROTOCOLS.has(proto)) return ORIGIN_WEB;
  return ORIGIN_UNTRUSTED;
}

/**
 * 一份“暴露计划”：preload 只应照它执行，避免在 preload 里散落 if 判断。
 *   exposeAPI：是否注入完整 electronAPI（含 send/invoke/on）；
 *   privileged：是否是受信内部上下文（exposeAPI 与之同真假，单独给出便于语义化）；
 *   origin：分类结果；
 *   cspReporter：是否安装 CSP 上报监听。远程页也允许装（主进程会按帧来源丢弃非
 *                内部上报），因此它不依赖 privileged，恒为 true。
 * @param {string} rawUrl
 * @returns {{exposeAPI:boolean, privileged:boolean, origin:string, cspReporter:boolean}}
 */
function buildExposure(rawUrl) {
  const origin = classifyLocation(rawUrl);
  const privileged = origin === ORIGIN_SHELL_FILE || origin === ORIGIN_INTERNAL_COSY;
  return {
    exposeAPI: privileged,
    privileged,
    origin,
    cspReporter: true,
  };
}

/**
 * 从“候选通道全集”里挑出当前上下文允许暴露的通道名，返回数组（保持稳定顺序）。
 * 内部上下文原样放行；远程上下文返回空集合。单独提供是为了让 preload 即使将来要
 * 给远程页保留极少数只读通道，也只能经由这里的白名单收敛，而不是随手放开。
 * @param {string} rawUrl
 * @param {Iterable<string>} channels
 * @returns {string[]}
 */
function selectChannels(rawUrl, channels) {
  if (!isInternalContext(rawUrl)) return [];
  const out = [];
  for (const ch of channels || []) {
    if (typeof ch === 'string') out.push(ch);
  }
  return out;
}

module.exports = {
  INTERNAL_PROTOCOLS,
  WEB_PROTOCOLS,
  ORIGIN_SHELL_FILE,
  ORIGIN_INTERNAL_COSY,
  ORIGIN_WEB,
  ORIGIN_UNTRUSTED,
  ORIGIN_UNKNOWN,
  parseProtocol,
  isInternalContext,
  classifyLocation,
  buildExposure,
  selectChannels,
};
