'use strict';
const { TITLE_ACCEPT, TITLE_HOLD, HOLD_BURST, HOLD_SAME, TITLE_SANITIZED, MAX_TITLE_LEN, TITLE_BURST_WINDOW_MS, TITLE_BURST_LIMIT, TITLE_LONG_WINDOW_MS, TITLE_LONG_LIMIT, TITLE_SAME_MS, MAX_FAVICONS, MAX_FAVICON_URL_LEN, sanitizeTabTitle } = require('./titleclean_core');
const { describeReasonFrom } = require('./reasontext');
const { pruneOlderThan, countSince } = require('./modutil_core');

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

const TITLE_REASON_TEXT = {
  [HOLD_BURST]: '网页高频修改标题（标题闪烁 / 伪加载），已临时收敛更新',
  [HOLD_SAME]: '网页短时间重复上报相同标题，已忽略',
  [TITLE_SANITIZED]: '标签标题含控制字符或超长，已净化',
};

function describeTitleReason(reason) {
  return describeReasonFrom(TITLE_REASON_TEXT, reason, '标签标题更新');
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
