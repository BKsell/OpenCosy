'use strict';

// tabsearch.js —— “搜索已打开标签页”的纯逻辑内核（不碰 DOM、不碰 Electron）。
//
// 现代 Chrome/Edge 都有标签搜索：标签一多时用关键字在所有打开的标题/网址里过滤，
// 回车直接切过去。OpenCosy 之前没有这个能力。匹配/排序规则全部收口在这里，
// 主进程拿到权威 tabs 列表后调用 searchTabs，渲染层只负责呈现与键盘交互。
//
// 设计约束：
//   - 不使用正则（项目硬约束）。全部匹配走 indexOf / 逐字符判定。
//   - 多关键字 AND：拆出的每个 token 都必须在标题或网址里命中，缺一即排除。
//   - 标题权重高于网址；起始命中高于词边界命中，词边界命中高于普通包含。
//   - 排序对同分结果保持输入顺序稳定（稳定排序），固定标签给一个很小的恒定加权，
//     只在“相关度相同”时让固定标签靠前，不允许固定加权盖过真实相关度。
//   - 全程对输入做类型/长度净化：页面标题完全由网页控制，可能是超长串或非字符串。

const MAX_QUERY_LEN = 256;   // 搜索框输入长度上限，超过按前 256 字符处理
const MAX_TAB_INPUT = 100000; // 参与搜索的标签数量上限（纯防御，正常远小于此）
const MAX_RESULTS = 50;      // 下拉最多展示条数，再多没有可读价值也浪费渲染

// 评分权重。标题是用户最常识别标签的依据，整体高于网址；同位置起始命中最高。
const SCORE = Object.freeze({
  TITLE_PREFIX: 100,   // token 位于标题开头
  TITLE_WORD: 60,      // token 位于标题里的某个词边界之后
  TITLE_CONTAINS: 30,  // token 出现在标题其它位置
  HOST_PREFIX: 55,     // token 位于主机名开头
  HOST_CONTAINS: 32,   // token 位于主机名其它位置
  URL_CONTAINS: 12,    // token 位于网址路径/查询等其余部分
  PHRASE_BONUS: 40,    // 整个查询短语在标题开头连续出现
  PINNED_TIEBREAK: 2,  // 固定标签的同分微调，刻意很小
});

// isAsciiWhitespace 判定单个码元是否为需要切词的空白。
// 刻意只认 ASCII 空白与常见全角空格，不引入正则；其它 Unicode 空白（如 U+2003）
// 极难出现在用户手输的搜索词里，宁可漏切也不扩大特殊处理面。
function isSplitSpace(ch) {
  return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r'
    || ch === '\f' || ch === '\v' || ch === '　';
}

// tokenize 把查询切成小写、去重的关键字序列（保持首次出现顺序）。
// 连续空白折叠，不使用正则。
function tokenize(query) {
  const s = safeLower(query).slice(0, MAX_QUERY_LEN);
  const tokens = [];
  const seen = new Set();
  let cur = '';
  const push = () => {
    if (cur !== '' && !seen.has(cur)) {
      seen.add(cur);
      tokens.push(cur);
    }
    cur = '';
  };
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (isSplitSpace(ch)) {
      push();
    } else {
      cur += ch;
    }
  }
  push();
  return tokens;
}

// safeLower 把任意输入安全转成小写字符串：非字符串归空串，避免对 null/数字调方法抛错。
function safeLower(v) {
  if (typeof v !== 'string') return '';
  return v.toLowerCase();
}

// safeText 把标题/网址字段净化成可参与匹配的字符串：非字符串归空，长度裁剪防爆。
function safeText(v) {
  if (typeof v !== 'string') return '';
  return v.length > MAX_QUERY_LEN * 16 ? v.slice(0, MAX_QUERY_LEN * 16) : v;
}

// isWordBoundary 判断 pos 之前一个字符是否可视为“词边界”：
// 字符串开头，或前一字符不是字母/数字（空格、/、:、.、-、_、?、= 等都算）。
function isWordBoundary(text, pos) {
  if (pos <= 0) return true;
  const code = text.charCodeAt(pos - 1);
  const isDigit = code >= 48 && code <= 57;                 // 0-9
  const isUpper = code >= 65 && code <= 90;                 // A-Z
  const isLower = code >= 97 && code <= 122;                // a-z
  return !(isDigit || isUpper || isLower);
}

// scoreAtPosition 计算单个 token 在一段文本里的最高命中分。
// prefixScore/wordScore/containsScore 分别对应起始、词边界、普通包含三档。
function scoreInText(text, token, prefixScore, wordScore, containsScore) {
  if (text === '' || token === '') return 0;
  const idx = text.indexOf(token);
  if (idx < 0) return 0;
  if (idx === 0) return prefixScore;
  if (isWordBoundary(text, idx)) return wordScore;
  // 继续找是否存在一个落在词边界上的命中（取第一个词边界命中即可）。
  let from = idx + 1;
  for (;;) {
    const next = text.indexOf(token, from);
    if (next < 0) break;
    if (isWordBoundary(text, next)) return wordScore;
    from = next + 1;
  }
  return containsScore;
}

// hostRange 返回网址里主机名片段（不含协议与端口的大写归一交给调用方 toLowerCase）。
// 解析失败或没有明确主机结构时返回 null，由调用方退化为整段 URL 匹配。
function hostRange(urlLower) {
  const schemeEnd = urlLower.indexOf('://');
  if (schemeEnd < 0) return null;
  const start = schemeEnd + 3;
  let end = urlLower.indexOf('/', start);
  if (end < 0) end = urlLower.length;
  if (start >= end) return null;
  // 去掉 userinfo（user:pass@host）与端口，只保留主机名本身。
  let host = urlLower.slice(start, end);
  const at = host.lastIndexOf('@');
  if (at >= 0) host = host.slice(at + 1);
  const colon = host.indexOf(':');
  if (colon >= 0) host = host.slice(0, colon);
  return { start, end, host };
}

// scoreUrl 计算单个 token 在网址上的得分：主机名优先，其次路径/查询等其余部分。
function scoreUrl(urlLower, token) {
  if (urlLower === '' || token === '') return 0;
  const hr = hostRange(urlLower);
  if (hr) {
    const inHost = hr.host.indexOf(token);
    if (inHost === 0) return SCORE.HOST_PREFIX;
    if (inHost > 0) {
      // 主机名里的点边界（如 token 在 .example 的 example 处）按词边界对待。
      const before = hr.host[inHost - 1];
      if (before === '.' || before === '-') return SCORE.HOST_CONTAINS;
      return SCORE.HOST_CONTAINS - 8; // 仍算主机命中，略低于边界命中
    }
    // 主机没命中，再看路径/查询整段。
    const tail = urlLower.slice(hr.end);
    if (tail.indexOf(token) >= 0) return SCORE.URL_CONTAINS;
    // 协议段（http/https）命中价值极低，给一个保底小分。
    if (urlLower.slice(0, hr.start).indexOf(token) >= 0) return 1;
    return 0;
  }
  // 非标准网址（about:、cosy: 等）退化为整段包含匹配。
  return urlLower.indexOf(token) >= 0 ? SCORE.URL_CONTAINS : 0;
}

// normalizeTab 把一条标签记录净化为内核使用的内部形态。
function normalizeTab(raw, index) {
  const t = raw && typeof raw === 'object' ? raw : {};
  return {
    index,
    id: (typeof t.id === 'string' || typeof t.id === 'number') ? t.id : '',
    title: safeText(t.title),
    url: safeText(t.url),
    pinned: t.pinned === true || t.pinned === 1,
  };
}

// scoreTab 计算一条标签对全部 token 的总分；任一 token 在标题和网址都未命中返回 -1。
function scoreTab(tab, tokens) {
  const titleLower = tab.title.toLowerCase();
  const urlLower = tab.url.toLowerCase();
  let total = 0;
  for (const token of tokens) {
    const inTitle = titleLower.indexOf(token) >= 0;
    const inUrl = urlLower.indexOf(token) >= 0;
    if (!inTitle && !inUrl) return -1;
    if (inTitle) {
      total += scoreInText(titleLower, token,
        SCORE.TITLE_PREFIX, SCORE.TITLE_WORD, SCORE.TITLE_CONTAINS);
    }
    if (inUrl) {
      total += scoreUrl(urlLower, token);
    }
  }
  // 整个查询短语（以单个空格连接的原始小写串）若在标题开头连续出现，额外加权。
  if (tokens.length > 1) {
    const phrase = tokens.join(' ');
    if (titleLower.indexOf(phrase) === 0) total += SCORE.PHRASE_BONUS;
  }
  if (tab.pinned) total += SCORE.PINNED_TIEBREAK;
  return total;
}

// rankResult 是一条命中结果。
function rankResult(tab, score) {
  return {
    id: tab.id,
    index: tab.index,
    title: tab.title,
    url: tab.url,
    pinned: tab.pinned,
    score,
  };
}

// searchTabs 在已打开标签里搜索。返回按相关度降序（同分稳定）的精简结果数组。
// query 为空时返回固定标签在前、其余保持原顺序的前 MAX_RESULTS 条，方便浏览与定位。
function searchTabs(tabs, query) {
  const list = Array.isArray(tabs) ? tabs.slice(0, MAX_TAB_INPUT) : [];
  const tokens = tokenize(query);

  // 空查询：不做相关性过滤，仅按“固定在前 + 原顺序”给出一个稳定预览。
  if (tokens.length === 0) {
    const out = [];
    for (let i = 0; i < list.length && out.length < MAX_RESULTS; i++) {
      out.push(rankResult(normalizeTab(list[i], i), 0));
    }
    out.sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      return a.index - b.index;
    });
    return out;
  }

  const scored = [];
  for (let i = 0; i < list.length; i++) {
    const tab = normalizeTab(list[i], i);
    const s = scoreTab(tab, tokens);
    if (s >= 0) scored.push({ tab, score: s });
  }
  // 稳定排序：先按分数降序，同分回退到原始索引升序。
  scored.sort((a, b) => (b.score - a.score) || (a.tab.index - b.tab.index));

  const out = [];
  for (let i = 0; i < scored.length && out.length < MAX_RESULTS; i++) {
    out.push(rankResult(scored[i].tab, scored[i].score));
  }
  return out;
}

module.exports = {
  MAX_QUERY_LEN,
  MAX_TAB_INPUT,
  MAX_RESULTS,
  SCORE,
  tokenize,
  isWordBoundary,
  scoreInText,
  hostRange,
  scoreUrl,
  scoreTab,
  normalizeTab,
  searchTabs,
};
