"use strict";

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

module.exports = { TITLE_ACCEPT, TITLE_HOLD, HOLD_BURST, HOLD_SAME, TITLE_SANITIZED, MAX_TITLE_LEN, TITLE_BURST_WINDOW_MS, TITLE_BURST_LIMIT, TITLE_LONG_WINDOW_MS, TITLE_LONG_LIMIT, TITLE_SAME_MS, MAX_FAVICONS, MAX_FAVICON_URL_LEN, sanitizeTabTitle };
