'use strict';

// mediaguard.js —— 媒体播放状态事件（media-started-playing / media-paused）收口内核。
//
// 威胁模型：
//   Chromium 在媒体开始/暂停播放时向主进程抛事件，浏览器据此更新标签页声音图标、
//   托盘/系统媒体控制（MPRIS、媒体键、锁屏控件）、无障碍播报等。恶意页面可以：
//     1) 自动播放风暴：插入大量 <video>/<audio> 并高频 play()/pause()，让标签声音
//        状态、系统媒体会话、托盘图标每秒抖动成百上千次，打爆 IPC 与系统媒体服务；
//     2) 媒体键劫持：持续抢占“正在播放”会话，拦截用户的播放/暂停硬件键；
//     3) 重复同态事件：已经在播放时继续抛 started，纯空转。
//   裁决：维护播放布尔态，只有真正翻转才通知上层（accept）；同态重复与高频翻转做
//   软合并（hold）；所有事件（含被合并的）计入滑动窗口硬洪泛，越限进冷却整体丢弃，
//   避免被节流的事件空转拖死主进程。纯函数，无 DOM 依赖。

const MEDIA_STARTED = 'started';
const MEDIA_PAUSED = 'paused';

const MEDIA_ACCEPT = 'accept'; // 播放态真实翻转，允许更新声音图标/媒体会话
const MEDIA_HOLD = 'hold';     // 同态重复或过于频繁，合并
const MEDIA_DROP = 'drop';     // 洪泛/冷却期，按攻击行为丢弃

const HOLD_REDUNDANT = 'media-redundant-transition';
const HOLD_TOO_SOON = 'media-too-soon';
const DROP_BAD_EVENT = 'media-bad-event';
const DROP_FLOOD = 'media-flood-exceeded';
const DROP_COOLDOWN = 'media-cooldown-active';

const MEDIA_MIN_INTERVAL_MS = 100;
const MEDIA_BURST_WINDOW_MS = 1_000;
const MEDIA_BURST_LIMIT = 30;
const MEDIA_LONG_WINDOW_MS = 10_000;
const MEDIA_LONG_LIMIT = 200;
const MEDIA_COOLDOWN_MS = 4_000;

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

function createMediaState(now) {
  return {
    times: [],
    accepted: 0,
    held: 0,
    dropped: 0,
    playing: false,
    lastFlipAt: 0,
    cooldownUntil: 0,
    createdAt: now || 0,
  };
}

function resetForNavigation(state) {
  if (!state) return;
  state.times = [];
  state.playing = false;
  state.lastFlipAt = 0;
  state.cooldownUntil = 0;
}

// decideMediaEvent 裁决一次媒体事件。event 必须是 'started' 或 'paused'。
function decideMediaEvent(state, event, now) {
  if (!state) throw new TypeError('mediaguard: state required');
  const wantPlaying = event === MEDIA_STARTED ? true : (event === MEDIA_PAUSED ? false : null);
  const baseCounts = () => ({
    burstCount: countSince(state.times, now - MEDIA_BURST_WINDOW_MS),
    longCount: state.times.length, droppedTotal: state.dropped,
    playing: state.playing,
  });

  if (wantPlaying === null) {
    state.dropped += 1;
    return { action: MEDIA_DROP, reason: DROP_BAD_EVENT, ...baseCounts() };
  }

  const inCooldownBefore = state.cooldownUntil > now;
  state.times.push(now);
  pruneOlderThan(state.times, now - MEDIA_LONG_WINDOW_MS);
  const burst = countSince(state.times, now - MEDIA_BURST_WINDOW_MS);
  let flood = null;
  if (burst > MEDIA_BURST_LIMIT || state.times.length > MEDIA_LONG_LIMIT) {
    state.cooldownUntil = now + MEDIA_COOLDOWN_MS;
    flood = { reason: DROP_FLOOD, burstCount: burst, longCount: state.times.length };
  }

  if (state.cooldownUntil > now || flood) {
    state.dropped += 1;
    return {
      action: MEDIA_DROP,
      reason: inCooldownBefore ? DROP_COOLDOWN : (flood ? flood.reason : DROP_COOLDOWN),
      burstCount: flood ? flood.burstCount : burst,
      longCount: flood ? flood.longCount : state.times.length,
      cooldownUntil: state.cooldownUntil, droppedTotal: state.dropped, playing: state.playing,
    };
  }
  if (state.cooldownUntil > 0 && state.cooldownUntil <= now) state.cooldownUntil = 0;

  // 同态重复（播放中又 started / 已暂停又 paused）：合并，不翻转。
  if (wantPlaying === state.playing) {
    state.held += 1;
    return { action: MEDIA_HOLD, reason: HOLD_REDUNDANT, ...baseCounts() };
  }
  // 翻转过快：保留内部目标态为“期望值”但不刷新 UI，等下一次合法翻转对齐。
  // 这里选择不改 state.playing，让真实媒体态由后续合法事件收敛，避免 UI 抖动。
  if (now - state.lastFlipAt < MEDIA_MIN_INTERVAL_MS && state.lastFlipAt !== 0) {
    state.held += 1;
    return { action: MEDIA_HOLD, reason: HOLD_TOO_SOON, ...baseCounts() };
  }

  state.accepted += 1;
  state.playing = wantPlaying;
  state.lastFlipAt = now;
  return { action: MEDIA_ACCEPT, reason: '', ...baseCounts() };
}

function describeMediaReason(reason) {
  switch (reason) {
    case HOLD_REDUNDANT:
      return '重复的媒体播放状态事件已合并';
    case HOLD_TOO_SOON:
      return '媒体播放/暂停切换过于频繁，已合并声音状态刷新';
    case DROP_BAD_EVENT:
      return '未知类型的媒体事件已忽略';
    case DROP_FLOOD:
      return '页面异常频繁切换媒体播放状态（疑似自动播放风暴/媒体键劫持），冷却期内冻结声音指示';
    case DROP_COOLDOWN:
      return '媒体播放风暴冷却期内的状态事件已忽略';
    default:
      return '媒体播放状态';
  }
}

module.exports = {
  MEDIA_STARTED,
  MEDIA_PAUSED,
  MEDIA_ACCEPT,
  MEDIA_HOLD,
  MEDIA_DROP,
  HOLD_REDUNDANT,
  HOLD_TOO_SOON,
  DROP_BAD_EVENT,
  DROP_FLOOD,
  DROP_COOLDOWN,
  MEDIA_MIN_INTERVAL_MS,
  MEDIA_BURST_WINDOW_MS,
  MEDIA_BURST_LIMIT,
  MEDIA_LONG_WINDOW_MS,
  MEDIA_LONG_LIMIT,
  MEDIA_COOLDOWN_MS,
  createMediaState,
  resetForNavigation,
  decideMediaEvent,
  describeMediaReason,
};
