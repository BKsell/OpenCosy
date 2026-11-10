'use strict';
const { describeReasonFrom } = require('./reasontext');
const { pruneOlderThan, countSince } = require('./modutil');

const {
  DROP_BAD,
  DROP_COOLDOWN,
  DROP_FLOOD,
  HOLD_SAME,
  HOVER_BURST_WINDOW_MS,
  HOVER_LONG_WINDOW_MS,
  HOVER_MIN_INTERVAL_MS,
  HOVER_SHOW,
  noteAttempt,
  sanitizeHoverUrl
} = require('./hoverguard_rules');

// decideHoverUrl 裁决一次 update-target-url。
function decideHoverUrl(state, rawUrl, now) {
  if (!state) throw new TypeError('hoverguard: state required');
  const clean = sanitizeHoverUrl(rawUrl);
  const baseCounts = () => ({
    burstCount: countSince(state.times, now - HOVER_BURST_WINDOW_MS),
    longCount: state.times.length, droppedTotal: state.dropped,
  });

  if (!clean.ok) {
    state.dropped += 1;
    return { action: HOVER_DROP, reason: DROP_BAD, url: '', truncated: false, ...baseCounts() };
  }

  // 冷却期内除清空信号外一律丢弃；清空信号在下面单独放行，避免攻击者让状态栏卡在假地址。
  const inCooldownBefore = state.cooldownUntil > now;
  // 每一次事件都计入硬洪泛（含被软节流合并的）；清空信号也计数，但即便它正好
  // 越限也必须送达——否则状态栏永远清不掉。越限会刷新冷却，随后的普通链接照丢。
  const flood = noteAttempt(state, now);

  if (clean.empty) {
    if (state.lastUrl === '' && state.lastShownAt !== 0) {
      state.held += 1;
      return { action: HOVER_HOLD, reason: HOLD_SAME, url: '', truncated: false, ...baseCounts() };
    }
    state.lastUrl = '';
    state.lastShownAt = now;
    state.shown += 1;
    return { action: HOVER_SHOW, reason: '', url: '', truncated: false, ...baseCounts() };
  }

  if (state.cooldownUntil > now || flood) {
    state.dropped += 1;
    const reason = inCooldownBefore ? DROP_COOLDOWN : (flood ? flood.reason : DROP_COOLDOWN);
    return {
      action: HOVER_DROP, reason,
      url: clean.url, truncated: clean.truncated,
      burstCount: flood ? flood.burstCount : countSince(state.times, now - HOVER_BURST_WINDOW_MS),
      longCount: flood ? flood.longCount : state.times.length,
      cooldownUntil: state.cooldownUntil, droppedTotal: state.dropped,
    };
  }

  // 冷却已过：恢复正常裁决。
  if (state.cooldownUntil > 0 && state.cooldownUntil <= now) state.cooldownUntil = 0;

  if (clean.url === state.lastUrl && now - state.lastShownAt < HOVER_LONG_WINDOW_MS) {
    state.held += 1;
    return { action: HOVER_HOLD, reason: HOLD_SAME, url: clean.url, truncated: clean.truncated, ...baseCounts() };
  }
  if (now - state.lastShownAt < HOVER_MIN_INTERVAL_MS && state.lastShownAt !== 0) {
    state.held += 1;
    return { action: HOVER_HOLD, reason: HOLD_TOO_SOON, url: clean.url, truncated: clean.truncated, ...baseCounts() };
  }

  state.shown += 1;
  state.lastUrl = clean.url;
  state.lastShownAt = now;
  return { action: HOVER_SHOW, reason: '', url: clean.url, truncated: clean.truncated, ...baseCounts() };
}

const HOVER_REASON_TEXT = {
  [HOLD_TOO_SOON]: '悬停目标更新过于频繁，已合并本次状态栏刷新',
  [HOLD_SAME]: '悬停目标未变化，状态栏无需刷新',
  [DROP_BAD]: '非文本类型的悬停目标已忽略',
  [DROP_FLOOD]: '悬停目标变更异常频繁（疑似点击劫持/洪泛），冷却期内停止预告',
  [DROP_COOLDOWN]: '悬停洪泛冷却期内的目标变更已忽略',
};

function describeHoverReason(reason) {
  return describeReasonFrom(HOVER_REASON_TEXT, reason, '悬停目标');
}
