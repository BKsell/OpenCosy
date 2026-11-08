'use strict';

// unloadguard.js —— 页面 beforeunload 强留页（will-prevent-unload）滥用收口内核。
//
// 威胁模型：
//   页面注册 beforeunload 并 preventDefault 后，Electron 会触发 webContents 的
//   'will-prevent-unload'。应用旧实现无条件弹一个“离开 / 留下”的原生模态框并
//   preventDefault，恶意页可以借此：
//     1) 用户每次想关标签 / 后退 / 跳转都被模态框打断（强留页 / 拒绝服务）；
//     2) 脚本反复触发会卸载又取消的导航，制造“永远关不掉”的弹窗轰炸；
//     3) 配合诱导文案让用户习惯性点“留下”，困在钓鱼 / 诈骗页。
//   Electron 的裁决语义：在 'will-prevent-unload' 里调用 event.preventDefault()
//   表示“尊重页面、阻止本次卸载”；不调用则页面照常卸载（用户顺利离开）。
//   因此本内核用“每个页面生命周期的滑动窗口配额 + 冷却”收敛：
//     - 同一页面在短窗口内最多弹 UNLOAD_BURST_LIMIT 次确认，给真实“未保存修改”留额度；
//     - 越限后直接 LEAVE（不 preventDefault），让关闭 / 导航生效，并进入冷却；
//     - 一次成功的主导航（did-navigate）视为进入新页面，配额重置。

const UNLOAD_ASK = 'ask';     // 尊重 beforeunload，弹原生确认
const UNLOAD_LEAVE = 'leave'; // 忽略强留页，允许卸载

const LEAVE_BURST = 'unload-burst-exceeded';
const LEAVE_COOLDOWN = 'unload-cooldown-active';

const UNLOAD_BURST_WINDOW_MS = 15_000;
const UNLOAD_BURST_LIMIT = 2;
const UNLOAD_LONG_WINDOW_MS = 60_000;
const UNLOAD_LONG_LIMIT = 5;
const UNLOAD_COOLDOWN_MS = 20_000;

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

function createUnloadState(now) {
  return {
    promptTimes: [],
    askCount: 0,
    leaveCount: 0,
    cooldownUntil: 0,
    burstReportedAt: 0,
    createdAt: now || 0,
  };
}

// resetForNavigation 在一次成功主导航后调用：新页面应当重新获得完整的确认额度。
function resetForNavigation(state) {
  if (!state) return;
  state.promptTimes = [];
  state.cooldownUntil = 0;
}

// decideUnload 裁决一次 will-prevent-unload。
// 返回 { decision, reason, burstCount, longCount, cooldownUntil }。
function decideUnload(state, now) {
  if (!state) {
    return {
      decision: UNLOAD_LEAVE, reason: LEAVE_BURST,
      burstCount: 0, longCount: 0, cooldownUntil: 0,
    };
  }

  if (state.cooldownUntil > now) {
    state.promptTimes.push(now);
    pruneOlderThan(state.promptTimes, now - UNLOAD_LONG_WINDOW_MS);
    state.leaveCount += 1;
    return {
      decision: UNLOAD_LEAVE, reason: LEAVE_COOLDOWN,
      burstCount: countSince(state.promptTimes, now - UNLOAD_BURST_WINDOW_MS),
      longCount: state.promptTimes.length,
      cooldownUntil: state.cooldownUntil,
    };
  }

  state.promptTimes.push(now);
  pruneOlderThan(state.promptTimes, now - UNLOAD_LONG_WINDOW_MS);
  const longCount = state.promptTimes.length;
  const burstCount = countSince(state.promptTimes, now - UNLOAD_BURST_WINDOW_MS);

  if (burstCount > UNLOAD_BURST_LIMIT || longCount > UNLOAD_LONG_LIMIT) {
    state.cooldownUntil = now + UNLOAD_COOLDOWN_MS;
    state.leaveCount += 1;
    if (burstCount > UNLOAD_BURST_LIMIT) state.burstReportedAt = now;
    return {
      decision: UNLOAD_LEAVE, reason: LEAVE_BURST,
      burstCount, longCount, cooldownUntil: state.cooldownUntil,
    };
  }

  state.askCount += 1;
  return {
    decision: UNLOAD_ASK, reason: '',
    burstCount, longCount, cooldownUntil: 0,
  };
}

function resetCooldown(state) {
  if (state) state.cooldownUntil = 0;
}

function describeUnloadReason(reason) {
  switch (reason) {
    case LEAVE_BURST:
      return '网页反复阻止离开（强留页），本次已直接放行关闭/导航';
    case LEAVE_COOLDOWN:
      return '强留页冷却期内的拦截已忽略，允许离开';
    default:
      return '离开确认';
  }
}

module.exports = {
  UNLOAD_ASK,
  UNLOAD_LEAVE,
  LEAVE_BURST,
  LEAVE_COOLDOWN,
  UNLOAD_BURST_WINDOW_MS,
  UNLOAD_BURST_LIMIT,
  UNLOAD_LONG_WINDOW_MS,
  UNLOAD_LONG_LIMIT,
  UNLOAD_COOLDOWN_MS,
  createUnloadState,
  resetForNavigation,
  decideUnload,
  resetCooldown,
  describeUnloadReason,
};
