'use strict';

const READER_MIN_ARTICLE_CHARS = 200; // 低于该长度认为“没有可抽取正文”
const READER_WPM = 450;              // 中文为主的阅读速度（字/分钟）估算

// linkDensity 返回容器文本中“位于链接内”的字符占比（0~1）。导航 / 相关阅读段落该值接近 1。
function linkDensity(linkTextLength, textLength) {
  if (!(textLength > 0)) return 0;
  const r = linkTextLength / textLength;
  return r > 1 ? 1 : r;
}

// 句读密度：中文逗号/句号/顿号/分号/问号/感叹号与英文逗号句号的占比线索，正文高于菜单。
function punctuationCount(text) {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '，' || ch === '。' || ch === '、' || ch === '；' || ch === '?' ||
      ch === '！' || ch === '？' || ch === ',' || ch === '.' || ch === '!' || ch === ':') {
      n++;
    }
  }
  return n;
}

// scoreContainer 依据“候选摘要”给正文容器打分。入参是已经汇总好的纯数据（不依赖 DOM），
// 便于在测试里直接构造。linkDensity 越高越像链接农场，惩罚越重。
function scoreContainer(s) {
  if (!s) return -Infinity;
  const text = Math.max(0, s.textLength | 0);
  const paragraphs = Math.max(0, s.paragraphCount | 0);
  const density = linkDensity(s.linkTextLength | 0, text);
  const punct = punctuationCount(typeof s.textSample === 'string' ? s.textSample : '');
  let score = text;
  score += paragraphs * 40;
  score += Math.min(punct, 200) * 2;
  score -= density * text * 1.5;
  if (s.semanticArticle) score += 500; // <article>/<main> 明确语义，额外加权
  if (s.semanticMain) score += 300;
  if (s.noise) score -= 800;
  return Math.round(score);
}

// cleanTitle 清理文档标题里的站点后缀。保守做法：只在“分隔符后片段较短（像站名而非标题）”
// 时裁掉，且不使用正则。多个分隔符取最靠右、且右侧不超过 24 字的那一个。
function cleanTitle(rawTitle) {
  let title = collapseSpaces(rawTitle).trim();
  if (title === '') return '';
  const separators = [' | ', ' || ', ' - ', ' – ', ' — ', ' :: ', ' · ', ' » ', ' * '];
  let best = -1;
  for (const sep of separators) {
    const idx = title.lastIndexOf(sep);
    if (idx > 0) {
      const tailLen = title.length - (idx + sep.length);
      if (tailLen > 0 && tailLen <= 24 && idx > best) best = idx;
    }
  }
  if (best > 0) title = title.slice(0, best).trim();
  return title;
}

function estimateReadMinutes(textLength) {
  if (!(textLength > 0)) return 1;
  return Math.max(1, Math.round(textLength / READER_WPM));
}

function clampInt(v, lo, hi) {
  v = Number(v);
  if (!Number.isFinite(v)) v = lo;
  v = Math.floor(v);
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

function isWhitespaceCode(code) {
  return code === 32 || code === 9 || code === 10 || code === 11 || code === 12 ||
    code === 13 || code === 0x85 || code === 0xa0 || code === 0x3000;
}

// collapseSpaces 把连续空白（含中文全角空格 / 不间断空格）折叠为单个普通空格，
// 不使用正则。用于抽取时把跨节点换行的文本归一。
function collapseSpaces(s) {
  s = String(s == null ? '' : s);
  let out = '';
  let pending = false;
  for (let i = 0; i < s.length; i++) {
    if (isWhitespaceCode(s.charCodeAt(i))) {
      pending = true;
      continue;
    }
    if (pending) {
      if (out !== '') out += ' ';
      pending = false;
    }
    out += s[i];
  }
  if (pending && out !== '') out += ' ';
  return out;
}

module.exports = {
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
};
