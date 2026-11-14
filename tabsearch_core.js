
const { MAX_QUERY_LEN, MAX_RESULTS, MAX_TAB_INPUT, SCORE, hostRange, isSplitSpace, isWordBoundary, safeLower, safeText, scoreInText, tokenize } = require('./tabsearch_ops_core');
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
