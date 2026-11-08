'use strict';

// printguard.js —— 网页 window.print() 打印请求的滥用/DoS 收口内核。
//
// 威胁模型：
//   window.print() 会拉起系统/应用的模态打印对话框。恶意页可以在
//   onafterprint / onbeforeprint 或定时器里递归、循环调用 print()，结果是一个刚关掉
//   下一个立刻弹出的模态框轰炸——模态期间主界面无法正常操作，等同拒绝服务；在某些
//   平台上还会排队占用打印子系统。Electron 的 webContents 'print' 事件可
//   preventDefault() 抑制掉这次内置打印流程，因此用“滑动窗口配额 + 冷却”收敛：
//
//     - 短窗口（10s）最多 PRINT_BURST_LIMIT 次，挡住连点/递归；
//     - 长窗口（60s）最多 PRINT_LONG_LIMIT 次，挡住低频但持续的骚扰；
//     - 任一窗口越限即进入冷却，冷却期内全部抑制，冷却结束后配额自然滑窗恢复。
//
//   正常用户一次页面最多打印一两份，配额足够宽松，不会误伤。
//   本模块只做纯判定，main.js 监听 'print' 事件、按结果 preventDefault 并留痕。

const PRINT_ALLOW = 'allow';
const PRINT_SUPPRESS = 'suppress';

const SUPPRESS_BURST = 'print-burst-exceeded';
const SUPPRESS_LONG = 'print-long-exceeded';
const SUPPRESS_COOLDOWN = 'print-cooldown-active';

const PRINT_BURST_WINDOW_MS = 10_000;
const PRINT_BURST_LIMIT = 2;
const PRINT_LONG_WINDOW_MS = 60_000;
const PRINT_LONG_LIMIT = 5;
const PRINT_COOLDOWN_MS = 30_000;

function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

function pruneOlderThan(list, cutoff) {
  let i = 0;
  while (i < list.length && list[i] < cutoff) i++;
  if (i > 0) list.splice(0, i);
}

function createPrintState(now) {
  return {
    origin: '',
    // 只保留长窗口长度即可统计两个窗口（短窗口是长窗口的子集）。
    requestTimes: [],
    suppressedCount: 0,
    allowedCount: 0,
    cooldownUntil: 0,
    burstReportedAt: 0,
    longReportedAt: 0,
    createdAt: now || 0,
  };
}

// inCooldown 判断当前是否处于打印冷却期（不修改状态）。
function inCooldown(state, now) {
  return !!state && state.cooldownUntil > now;
}

// decidePrint 判定一次打印请求是否放行。
// input: { originUrl?: string }
// 返回 { decision, reason, origin, burstCount, longCount, cooldownUntil }。
// 无论放行/抑制，本次请求时间戳都计入窗口（防止用“被抑制”探测或绕过统计）。
function decidePrint(state, input, now) {
  const inp = input || {};
  if (!state) {
    return {
      decision: PRINT_SUPPRESS, reason: SUPPRESS_BURST,
      origin: '', burstCount: 0, longCount: 0, cooldownUntil: 0,
    };
  }
  const origin = originFromUrl(inp.originUrl);
  if (origin) state.origin = origin;

  // 冷却期内一律抑制；冷却结束前不重复进入冷却（只刷新时间戳记录）。
  if (state.cooldownUntil > now) {
    state.requestTimes.push(now);
    pruneOlderThan(state.requestTimes, now - PRINT_LONG_WINDOW_MS);
    state.suppressedCount += 1;
    return {
      decision: PRINT_SUPPRESS, reason: SUPPRESS_COOLDOWN, origin,
      burstCount: countSince(state.requestTimes, now - PRINT_BURST_WINDOW_MS),
      longCount: state.requestTimes.length,
      cooldownUntil: state.cooldownUntil,
    };
  }

  state.requestTimes.push(now);
  pruneOlderThan(state.requestTimes, now - PRINT_LONG_WINDOW_MS);
  const longCount = state.requestTimes.length;
  const burstCount = countSince(state.requestTimes, now - PRINT_BURST_WINDOW_MS);

  let reason = '';
  if (burstCount > PRINT_BURST_LIMIT) {
    reason = SUPPRESS_BURST;
  } else if (longCount > PRINT_LONG_LIMIT) {
    reason = SUPPRESS_LONG;
  }

  if (reason) {
    state.cooldownUntil = now + PRINT_COOLDOWN_MS;
    state.suppressedCount += 1;
    if (reason === SUPPRESS_BURST) state.burstReportedAt = now;
    else state.longReportedAt = now;
    return {
      decision: PRINT_SUPPRESS, reason, origin,
      burstCount, longCount, cooldownUntil: state.cooldownUntil,
    };
  }

  state.allowedCount += 1;
  return {
    decision: PRINT_ALLOW, reason: '', origin,
    burstCount, longCount, cooldownUntil: 0,
  };
}

function countSince(sortedTimes, cutoff) {
  let n = 0;
  for (let i = sortedTimes.length - 1; i >= 0; i--) {
    if (sortedTimes[i] >= cutoff) n++;
    else break;
  }
  return n;
}

// resetCooldown 供“用户显式从某可信内部页打印”等场景手动解除（当前主流程不使用，
// 预留以便设置页加白），返回解除后的状态。
function resetCooldown(state) {
  if (state) state.cooldownUntil = 0;
}

function describePrintReason(reason) {
  switch (reason) {
    case SUPPRESS_BURST:
      return '网页在短时间内连续请求打印（疑似打印轰炸），本次已拦截';
    case SUPPRESS_LONG:
      return '网页持续高频请求打印，本次已拦截并进入冷却';
    case SUPPRESS_COOLDOWN:
      return '打印冷却期内的重复打印请求已拦截';
    default:
      return '打印请求';
  }
}

module.exports = {
  PRINT_ALLOW,
  PRINT_SUPPRESS,
  SUPPRESS_BURST,
  SUPPRESS_LONG,
  SUPPRESS_COOLDOWN,
  PRINT_BURST_WINDOW_MS,
  PRINT_BURST_LIMIT,
  PRINT_LONG_WINDOW_MS,
  PRINT_LONG_LIMIT,
  PRINT_COOLDOWN_MS,
  originFromUrl,
  createPrintState,
  inCooldown,
  decidePrint,
  resetCooldown,
  describePrintReason,
};
