'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'network-state-empty',
  BAD_STATE: 'network-state-bad',
  LONG_HOLD: 'network-state-long-hold',
  NO_REASON: 'network-state-no-reason',
  PRIVATE_STATE: 'network-state-private',
};

const STATES = ['online', 'offline', 'unknown', 'becoming-online'];
const MAX_HOLD_MS = 120000;

function evaluateNetworkState(snapshot, options) {
  const opts = options || {};
  const item = snapshot || {};
  const state = String(item.state || '').toLowerCase();
  if (state === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!STATES.includes(state)) {
    return { ok: false, blocked: true, reason: REASON.BAD_STATE, state: state.slice(0, 32) };
  }
  const hold = Number(item.holdMs);
  if (Number.isFinite(hold) && hold > (opts.maxHoldMs || MAX_HOLD_MS)) {
    return { ok: false, blocked: true, reason: REASON.LONG_HOLD, hold, limit: opts.maxHoldMs || MAX_HOLD_MS };
  }
  if (state === 'offline' && String(item.reason || '').trim() === '' && opts.requireReason !== false) {
    return { ok: false, blocked: false, reason: REASON.NO_REASON };
  }
  const serialized = JSON.stringify({ type: item.connectionType || '', effectiveType: item.effectiveType || '' });
  if (opts.redact === true && serialized.length > 0) {
    return {
      ok: true,
      blocked: false,
      reason: REASON.OK,
      state,
      redacted: { state, online: state === 'online' },
    };
  }
  return { ok: true, blocked: false, reason: REASON.OK, state, hold: Number.isFinite(hold) ? hold : 0 };
}

function toBanner(snapshot) {
  const item = snapshot || {};
  const state = String(item.state || 'unknown').toLowerCase();
  if (state === 'offline') return { text: '网络已断开，正在等待重连', severity: 'warning' };
  if (state === 'becoming-online') return { text: '网络正在恢复', severity: 'info' };
  if (state === 'online') return { text: '', severity: 'none' };
  return { text: '网络状态未知', severity: 'neutral' };
}

module.exports = {
  REASON,
  STATES,
  MAX_HOLD_MS,
  evaluateNetworkState,
  toBanner,
};
