'use strict';

// titleguard.js —— 标签页标题与网站图标的净化、长度与更新频率收口内核。
//
// 威胁模型：
//   document.title 与 <link rel=icon> 完全由页面控制，恶意页可以：
//     1) 标题塞入 NUL / 换页等控制字符、伪造换行制造“系统提示”假象（标题注入 / 钓鱼）；
//     2) title 里塞几万字符撑爆标签栏 DOM 与历史存储；
//     3) 在定时器里 document.title = 加载文案(1)... 高频翻转，既制造“永远在加载”假象，
//        又让主进程每条都 addToHistory + IPC 广播（CPU / 存储 / 渲染层 DoS）；
//     4) page-favicon-updated 一次给一大堆 data: URL（每个都可能很大），主进程旧实现
//        无脑取第一个，但数组本身的遍历与字符串处理仍可被喂大；非法 scheme 也需过滤。
//   本模块为纯函数 / 纯判定：
//     - sanitizeTabTitle 做类型收敛、控制字符剥离、空白折叠与代理项安全截断；
//     - decideTitleUpdate 做同值去抖 + 滑动窗口频率收敛；
//     - sanitizeFavicons 只保留 http(s)/data 图标、限制数量与单个长度。

const TITLE_ACCEPT = 'accept';
const TITLE_HOLD = 'hold'; // 频率越限：本轮不更新标签 / 不写历史 / 不广播

const HOLD_BURST = 'title-burst-exceeded';
const HOLD_SAME = 'title-unchanged';
const TITLE_SANITIZED = 'title-sanitized';

const MAX_TITLE_LEN = 300;
const TITLE_BURST_WINDOW_MS = 5_000;
const TITLE_BURST_LIMIT = 30;
const TITLE_LONG_WINDOW_MS = 30_000;
const TITLE_LONG_LIMIT = 120;
// 完全相同标题的去抖窗口：title 翻转动画常常“同一值-不同值”交替，相同值在极短时间内
// 重复上报没有意义。
const TITLE_SAME_MS = 200;

const MAX_FAVICONS = 4;
const MAX_FAVICON_URL_LEN = 8_192;

// sanitizeTabTitle 把页面上报的任意值收敛为可安全展示 / 入库的标签标题。
// 返回 { title, changed, truncated }。
function sanitizeTabTitle(raw) {
  let s;
  if (typeof raw === 'string') {
    s = raw;
  } else if (raw == null) {
    s = '';
  } else {
    s = String(raw);
  }
  const original = s;
  // 剥离除水平空白外的 C0/C1 控制字符（含 NUL、ESC、换页），再折叠所有空白为单空格。
  s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
  s = s.replace(/\s+/g, ' ').trim();
  const changedControl = s !== original.trim();

  // Array.from 按代码点切分，避免把代理对（emoji 等）从中间截断产生孤立代理。
  let truncated = false;
  const chars = Array.from(s);
  if (chars.length > MAX_TITLE_LEN) {
    s = chars.slice(0, MAX_TITLE_LEN).join('');
    truncated = true;
  }
  return { title: s, changed: changedControl || truncated, truncated };
}

function pruneOlderThan(list, cutoff) {
  let i = 0;
  while (i < list.length && list[i] < cutoff) i++;
  if (i > 0) list.splice(0, i);
}

function countSince(sortedTimes, cutoff) {
  let n = 0;
  for (let i = sortedTimes.length - 1; i >= 0; i--) {
    if (sortedTimes[i] >= cutoff) n++;
    else break;
  }
  return n;
}

function createTitleState(now) {
  return {
    updateTimes: [],
    acceptedCount: 0,
    heldCount: 0,
    lastTitle: '',
    lastAcceptedAt: 0,
    burstReportedAt: 0,
    createdAt: now || 0,
  };
}

// decideTitleUpdate 裁决一次 page-title-updated（内部先做 sanitize）。
// 返回 { decision, reason, title, burstCount, longCount, sanitized, truncated }。
function decideTitleUpdate(state, rawTitle, now) {
  const info = sanitizeTabTitle(rawTitle);
  const title = info.title;
  if (!state) {
    return {
      decision: TITLE_HOLD, reason: HOLD_BURST, title,
      burstCount: 0, longCount: 0, sanitized: info.changed, truncated: info.truncated,
    };
  }

  // 与上一次接受的标题完全相同且间隔极短：直接忽略（不更新、不写历史）。
  if (state.lastAcceptedAt && title === state.lastTitle &&
      now - state.lastAcceptedAt < TITLE_SAME_MS) {
    return {
      decision: TITLE_HOLD, reason: HOLD_SAME, title,
      burstCount: countSince(state.updateTimes, now - TITLE_BURST_WINDOW_MS),
      longCount: 0, sanitized: info.changed, truncated: info.truncated,
    };
  }

  state.updateTimes.push(now);
  pruneOlderThan(state.updateTimes, now - TITLE_LONG_WINDOW_MS);
  const longCount = state.updateTimes.length;
  const burstCount = countSince(state.updateTimes, now - TITLE_BURST_WINDOW_MS);

  if (burstCount > TITLE_BURST_LIMIT || longCount > TITLE_LONG_LIMIT) {
    state.heldCount += 1;
    if (burstCount > TITLE_BURST_LIMIT && !state.burstReportedAt) state.burstReportedAt = now;
    return {
      decision: TITLE_HOLD, reason: HOLD_BURST, title,
      burstCount, longCount, sanitized: info.changed, truncated: info.truncated,
    };
  }

  state.acceptedCount += 1;
  state.lastTitle = title;
  state.lastAcceptedAt = now;
  return {
    decision: TITLE_ACCEPT,
    reason: info.changed ? TITLE_SANITIZED : '',
    title, burstCount, longCount,
    sanitized: info.changed, truncated: info.truncated,
  };
}

// isAllowedFaviconScheme 只接受 http/https/data 三种来源的图标，
// 拒绝 file:/blob:/javascript: 等（旧实现已挡前缀，这里集中成判定）。
function isAllowedFaviconScheme(u) {
  if (typeof u !== 'string') return false;
  if (u.startsWith('data:')) return true;
  try {
    const parsed = new URL(u);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

// sanitizeFavicons 从 page-favicon-updated 的数组里挑出可用图标：
// 非字符串 / 超长 / 非法 scheme 一律丢弃，最多保留 MAX_FAVICONS 个，保持上报顺序。
function sanitizeFavicons(rawList) {
  const out = [];
  if (!Array.isArray(rawList)) return { favicons: out, dropped: 0 };
  let dropped = 0;
  for (let k = 0; k < rawList.length; k++) {
    const item = rawList[k];
    if (out.length >= MAX_FAVICONS) {
      dropped += rawList.length - k; // 剩余全部因超量未检查
      break;
    }
    if (typeof item !== 'string' || item.length === 0 ||
        item.length > MAX_FAVICON_URL_LEN || !isAllowedFaviconScheme(item)) {
      dropped++;
      continue;
    }
    out.push(item);
  }
  return { favicons: out, dropped };
}

// resolveFaviconHref 把以 '/' 开头的相对图标路径拼成绝对 URL；非法基址返回 ''。
function resolveFaviconHref(href, pageUrl) {
  if (typeof href !== 'string') return '';
  if (href.startsWith('/')) {
    try {
      return new URL(href, pageUrl).href;
    } catch {
      return '';
    }
  }
  return href;
}

function describeTitleReason(reason) {
  switch (reason) {
    case HOLD_BURST:
      return '网页高频修改标题（标题闪烁 / 伪加载），已临时收敛更新';
    case HOLD_SAME:
      return '网页短时间重复上报相同标题，已忽略';
    case TITLE_SANITIZED:
      return '标签标题含控制字符或超长，已净化';
    default:
      return '标签标题更新';
  }
}

module.exports = {
  TITLE_ACCEPT,
  TITLE_HOLD,
  HOLD_BURST,
  HOLD_SAME,
  TITLE_SANITIZED,
  MAX_TITLE_LEN,
  TITLE_BURST_WINDOW_MS,
  TITLE_BURST_LIMIT,
  TITLE_LONG_WINDOW_MS,
  TITLE_LONG_LIMIT,
  TITLE_SAME_MS,
  MAX_FAVICONS,
  MAX_FAVICON_URL_LEN,
  sanitizeTabTitle,
  createTitleState,
  decideTitleUpdate,
  isAllowedFaviconScheme,
  sanitizeFavicons,
  resolveFaviconHref,
  describeTitleReason,
};
