'use strict';

// consoleguard.js —— 渲染进程 console-message 事件的不可信输入收口内核。
//
// 威胁模型：
//   Electron 会把网页里 console.log/info/warn/error 等输出以 webContents 的
//   'console-message' 事件抛给主进程（event, level, message, line, sourceId）。
//   主进程一旦把这些字符串写进终端、日志文件或安全中心，恶意页面就能：
//     1) 日志注入：message 中夹带 \r、\n、U+2028/2029 换行，伪造出一条
//        “[安全] 已拦截危险下载”之类的假日志，污染审计链、误导排障；
//     2) 终端转义攻击：塞入 ESC[...m 等 ANSI 转义序列，在支持转义的终端里
//        移动光标、清屏、改背景色（老式终端还可借 OSC 序列外带数据）；
//     3) 洪泛：一个 setInterval 每秒刷几万条日志，打爆主进程日志文件 / 磁盘，
//        真正的安全事件被淹没（DoS + 证据灭失）；
//     4) 超长单行：单条几 MB 的 message 撑爆日志行与渲染层展示组件；
//     5) 伪造级别：level 不是 0..3 整数时按最普通 verbose 处理，绝不信任页面自封
//        的“error”级别去触发任何高优先级 UI。
//   本内核是纯函数：只负责净化与配额裁决，是否真正落日志由接线方决定。
//   配额模型与 unloadguard 一致：每页面短窗口突发上限 + 长窗口总量上限 + 冷却。

const CONSOLE_ACCEPT = 'accept'; // 内容已净化，允许落日志/转发
const CONSOLE_SKIP = 'skip';     // 净化后为空，无害但无信息，直接丢弃
const CONSOLE_DROP = 'drop';     // 洪泛/冷却期，按攻击行为丢弃

const CS_EMPTY = 'console-empty';
const CS_FLOOD = 'console-flood-exceeded';
const CS_COOLDOWN = 'console-cooldown-active';

// 单条文本净化后允许的最大代码点长度；超出截断并标注，宁可少记不可撑爆。
const CONSOLE_MAX_LINE_CHARS = 2048;
const CONSOLE_BURST_WINDOW_MS = 5_000;
const CONSOLE_BURST_LIMIT = 40;
const CONSOLE_LONG_WINDOW_MS = 60_000;
const CONSOLE_LONG_LIMIT = 300;
const CONSOLE_COOLDOWN_MS = 15_000;
// sourceId 是产生日志的脚本 URL，只留固定长度，防止异常超长 URL 连带污染。
const CONSOLE_MAX_SOURCE_CHARS = 512;

// ANSI 转义序列：ESC 后跟任意参数字节再跟一个终止字母，覆盖 CSI/OSC/单字符转义。
const ANSI_ESCAPE_RE = /\x1b(?:\[[0-9;?:<=>!#$%&()*+\-./ ^~]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|.)/g;
// 剩余 C0 控制字符（含 \r \n \t \x00、BEL 等）与 DEL；水平间隔类需求由调用方自行保留空格。
const C0_CONTROL_RE = /[\x00-\x1f\x7f]/g;
// JS 语境的换行分隔符，写进 JSON 日志也会断行，统一去掉。
const UNICODE_LINE_SEP_RE = new RegExp('[' + String.fromCharCode(0x2028, 0x2029) + ']', 'g');
// 零宽字符与 BOM 可用于肉眼混淆日志内容，展示前剥除。
const ZERO_WIDTH_RE = new RegExp('[' + String.fromCharCode(0x200b) + '-' + String.fromCharCode(0x200f) + String.fromCharCode(0x202a) + '-' + String.fromCharCode(0x202e) + String.fromCharCode(0x2060, 0xfeff) + ']', 'g');

// sanitizeConsoleText 把页面临控字符串收敛成“单行、无转义、有界”的安全文本。
// 返回 { text, truncated, length }；非字符串一律收敛为空串。
function sanitizeConsoleText(input, maxChars) {
  const limit = Number.isInteger(maxChars) && maxChars > 0 ? maxChars : CONSOLE_MAX_LINE_CHARS;
  if (typeof input !== 'string') {
    return { text: '', truncated: false, length: 0 };
  }
  let text = input
    .replace(ANSI_ESCAPE_RE, '')
    .replace(C0_CONTROL_RE, '')
    .replace(UNICODE_LINE_SEP_RE, '')
    .replace(ZERO_WIDTH_RE, '');

  const chars = Array.from(text);
  let truncated = false;
  if (chars.length > limit) {
    text = chars.slice(0, limit - 1).join('') + '…';
    truncated = true;
  }
  return { text, truncated, length: Array.from(text).length };
}

// normalizeConsoleLevel 只接受 Chromium 的 0..3（verbose/info/warning/error）。
function normalizeConsoleLevel(level) {
  if (Number.isInteger(level) && level >= 0 && level <= 3) return level;
  return 0;
}

// sanitizeSourceLocation 收敛 sourceId 与行号；行号非法一律记 0，不抛错。
function sanitizeSourceLocation(sourceId, line) {
  const src = sanitizeConsoleText(sourceId, CONSOLE_MAX_SOURCE_CHARS);
  let lineNo = 0;
  if (Number.isFinite(line) && line >= 0) lineNo = Math.min(Number(line), 0x7fffffff);
  return { sourceId: src.text, line: lineNo };
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

function createConsoleState(now) {
  return {
    times: [],
    acceptCount: 0,
    skipCount: 0,
    dropped: 0,
    cooldownUntil: 0,
    floodStartedAt: 0,
    createdAt: now || 0,
  };
}

// resetForNavigation 在主导航后调用：新页面重新获得完整日志配额，但累计丢弃数保留，
// 方便接线方在一个标签生命周期结束时汇总“该页共刷了多少被丢弃的日志”。
function resetForNavigation(state) {
  if (!state) return;
  state.times = [];
  state.cooldownUntil = 0;
}

// decideConsole 裁决一条 console-message。
// entry: { level, message, line, sourceId }。
// 返回 { action, reason, level, text, line, sourceId, truncated, burstCount, longCount,
//        droppedTotal }。
function decideConsole(state, entry, now) {
  if (!state) {
    throw new TypeError('consoleguard: state required');
  }
  const e = entry && typeof entry === 'object' ? entry : {};
  const level = normalizeConsoleLevel(e.level);
  const cleaned = sanitizeConsoleText(e.message);
  const loc = sanitizeSourceLocation(e.sourceId, e.line);

  if (cleaned.text.length === 0) {
    state.skipCount += 1;
    return {
      action: CONSOLE_SKIP, reason: CS_EMPTY, level,
      text: '', line: loc.line, sourceId: loc.sourceId, truncated: false,
      burstCount: countSince(state.times, now - CONSOLE_BURST_WINDOW_MS),
      longCount: state.times.length, droppedTotal: state.dropped,
    };
  }

  if (state.cooldownUntil > now) {
    state.dropped += 1;
    pruneOlderThan(state.times, now - CONSOLE_LONG_WINDOW_MS);
    return {
      action: CONSOLE_DROP, reason: CS_COOLDOWN, level,
      text: cleaned.text, line: loc.line, sourceId: loc.sourceId,
      truncated: cleaned.truncated,
      burstCount: countSince(state.times, now - CONSOLE_BURST_WINDOW_MS),
      longCount: state.times.length, droppedTotal: state.dropped,
    };
  }

  state.times.push(now);
  pruneOlderThan(state.times, now - CONSOLE_LONG_WINDOW_MS);
  const longCount = state.times.length;
  const burstCount = countSince(state.times, now - CONSOLE_BURST_WINDOW_MS);

  if (burstCount > CONSOLE_BURST_LIMIT || longCount > CONSOLE_LONG_LIMIT) {
    state.cooldownUntil = now + CONSOLE_COOLDOWN_MS;
    state.dropped += 1;
    if (!state.floodStartedAt) state.floodStartedAt = now;
    return {
      action: CONSOLE_DROP, reason: CS_FLOOD, level,
      text: cleaned.text, line: loc.line, sourceId: loc.sourceId,
      truncated: cleaned.truncated,
      burstCount, longCount, cooldownUntil: state.cooldownUntil,
      droppedTotal: state.dropped,
    };
  }

  state.acceptCount += 1;
  return {
    action: CONSOLE_ACCEPT, reason: '', level,
    text: cleaned.text, line: loc.line, sourceId: loc.sourceId,
    truncated: cleaned.truncated, burstCount, longCount, droppedTotal: state.dropped,
  };
}

function describeConsoleReason(reason) {
  switch (reason) {
    case CS_EMPTY:
      return '空白控制台输出已跳过';
    case CS_FLOOD:
      return '网页控制台输出频率异常（疑似日志洪泛），冷却期内的输出已丢弃';
    case CS_COOLDOWN:
      return '控制台洪泛冷却期内的输出已丢弃';
    default:
      return '控制台输出';
  }
}

module.exports = {
  CONSOLE_ACCEPT,
  CONSOLE_SKIP,
  CONSOLE_DROP,
  CS_EMPTY,
  CS_FLOOD,
  CS_COOLDOWN,
  CONSOLE_MAX_LINE_CHARS,
  CONSOLE_BURST_WINDOW_MS,
  CONSOLE_BURST_LIMIT,
  CONSOLE_LONG_WINDOW_MS,
  CONSOLE_LONG_LIMIT,
  CONSOLE_COOLDOWN_MS,
  CONSOLE_MAX_SOURCE_CHARS,
  sanitizeConsoleText,
  normalizeConsoleLevel,
  sanitizeSourceLocation,
  createConsoleState,
  resetForNavigation,
  decideConsole,
  describeConsoleReason,
};
