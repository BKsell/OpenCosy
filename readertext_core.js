const {
  isWhitespaceCode,
  collapseSpaces,
  READER_MIN_ARTICLE_CHARS,
  READER_WPM,
  linkDensity,
  punctuationCount,
  scoreContainer,
  cleanTitle,
  estimateReadMinutes,
  clampInt,
} = require('./readertextscore_core');

const SKIP_TAGS = new Set([
  'script', 'style', 'noscript', 'template', 'iframe', 'frame', 'object', 'embed',
  'applet', 'svg', 'canvas', 'form', 'input', 'button', 'select', 'textarea', 'option',
  'dialog', 'details', 'summary',
]);

// 打分阶段视为“噪音容器”的标签：页眉 / 导航 / 页脚 / 侧栏 / 广告槽，不参与最佳正文选举。
const NOISE_TAGS = new Set([
  'nav', 'aside', 'footer', 'header', 'address', 'menu',
]);

// 允许出现在最终阅读树里的“块级”标签。其余容器（div/section 等）不输出自身，
// 只把其中符合白名单的子节点提升上来，避免把版面 class/style 结构带进来。
const OUTPUT_BLOCK_TAGS = new Set([
  'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'blockquote', 'pre', 'ul', 'ol', 'li',
  'figure', 'figcaption', 'img', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
]);

// 允许在段落内保留的“内联”标签。链接只保留安全 href，其余内联只用于加粗 / 斜体 / 等宽。
const OUTPUT_INLINE_TAGS = new Set([
  'strong', 'b', 'em', 'i', 'code', 'kbd', 'samp', 'var', 'mark', 'small', 'sub', 'sup',
  'a', 'br', 'span', 'time', 'cite', 'q', 'abbr',
]);

// 可作为“正文容器”参与打分的标签。article/main 天然优先，语义/通用块容器作为候选。
const CONTAINER_TAGS = new Set([
  'article', 'main', 'section', 'div', 'td',
]);

const READER_MAX_NODES = 4000;       // 最终阅读树节点上限，防止超长页面把 IPC 撑爆
const READER_MAX_DEPTH = 24;         // 阅读树最大嵌套深度，挡异常深 DOM
const READER_MAX_TEXT_CHARS = 200000; // 正文总字符上限
const READER_MAX_LINK_CHARS = 2000;  // 单个链接锚文本上限

function normalizeTagName(nodeName) {
  return String(nodeName == null ? '' : nodeName).toLowerCase();
}

function isSkippable(tag) {
  return SKIP_TAGS.has(tag);
}

function isNoise(tag) {
  return NOISE_TAGS.has(tag);
}

function isOutputBlock(tag) {
  return OUTPUT_BLOCK_TAGS.has(tag);
}

function isOutputInline(tag) {
  return OUTPUT_INLINE_TAGS.has(tag);
}

function isContainer(tag) {
  return CONTAINER_TAGS.has(tag);
}

function elementText(el) {
  return el && typeof el.textContent === 'string' ? el.textContent : '';
}

// safeHref 只放行绝对的 http/https 链接：挡掉 javascript:/data:/vbscript: 等危险
// scheme、协议相对 URL（//host），以及无 scheme 的相对 / 纯锚点链接。阅读页跑在
// cosy: 源上，不保留原页面基址，相对链接无法安全解析成正确目标，统一降级为纯文本。
// 返回空字符串表示该链接不保留为可点链接。
function safeHref(raw) {
  let href = String(raw == null ? '' : raw).trim();
  if (href === '') return '';
  // 去掉控制字符，防止用换行 / Tab 在视觉上混淆 scheme。
  let cleaned = '';
  for (let i = 0; i < href.length; i++) {
    const code = href.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) continue;
    cleaned += href[i];
  }
  href = cleaned;
  if (href.charCodeAt(0) === 0x2f && href.charCodeAt(1) === 0x2f) return ''; // 协议相对 URL
  const colon = href.indexOf(':');
  if (colon < 0) return ''; // 无 scheme 的相对链接 / 纯锚点
  const scheme = href.slice(0, colon).toLowerCase();
  return scheme === 'http' || scheme === 'https' ? href : '';
}

// safeImageSrc 与 safeHref 同口径（阅读页图片同样只接受绝对 http/https）。
function safeImageSrc(raw) {
  return safeHref(raw);
}

// buildReaderExtractScriptBody 返回常量 + 同名判定函数 + DOM 抽取体，末尾
// `return extractArticle(document)`，不含 IIFE 外壳，便于测试以 new Function 注入假 DOM。

module.exports = {
  SKIP_TAGS,
  NOISE_TAGS,
  OUTPUT_BLOCK_TAGS,
  OUTPUT_INLINE_TAGS,
  CONTAINER_TAGS,
  READER_MAX_NODES,
  READER_MAX_DEPTH,
  READER_MAX_TEXT_CHARS,
  READER_MAX_LINK_CHARS,
  READER_MIN_ARTICLE_CHARS,
  READER_WPM,
  isWhitespaceCode,
  collapseSpaces,
  normalizeTagName,
  isSkippable,
  isNoise,
  isOutputBlock,
  isOutputInline,
  isContainer,
  elementText,
  safeHref,
  safeImageSrc,
  linkDensity,
  punctuationCount,
  scoreContainer,
  cleanTitle,
  estimateReadMinutes,
  clampInt,
};
