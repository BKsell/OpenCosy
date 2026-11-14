'use strict';

const DEFAULT_WINDOW_MS = 60 * 1000;
const DEFAULT_MAX_PER_KEY = 3;
const DEFAULT_MAX_KEYS = 512;

function normalizeKey(origin, permission) {
  const cleanOrigin = String(origin || '').trim().toLowerCase() || 'unknown-origin';
  const cleanPermission = String(permission || '').trim().toLowerCase() || 'unknown-permission';
  return `${cleanOrigin}|${cleanPermission}`;
}

function createDenyLedger(options = {}) {
  const windowMs = Number.isFinite(options.windowMs) && options.windowMs > 0
    ? Math.floor(options.windowMs)
    : DEFAULT_WINDOW_MS;
  const maxPerKey = Number.isFinite(options.maxPerKey) && options.maxPerKey > 0
    ? Math.floor(options.maxPerKey)
    : DEFAULT_MAX_PER_KEY;
  const maxKeys = Number.isFinite(options.maxKeys) && options.maxKeys > 0
    ? Math.floor(options.maxKeys)
    : DEFAULT_MAX_KEYS;
  const now = typeof options.now === 'function' ? options.now : () => Date.now();

  const states = new Map();
  let suppressed = 0;
  let total = 0;

  function prune(clock) {
    for (const [key, state] of states) {
      if (clock - state.windowStart >= windowMs) {
        states.delete(key);
      }
    }
    while (states.size > maxKeys) {
      const oldest = states.keys().next();
      if (oldest.done) break;
      states.delete(oldest.value);
    }
  }

  function record(input = {}) {
    const clock = Number.isFinite(input.now) ? input.now : now();
    const key = normalizeKey(input.origin, input.permission);
    const state = states.get(key);
    if (!state || clock - state.windowStart >= windowMs) {
      states.set(key, { count: 1, windowStart: clock, firstSeen: clock });
      total += 1;
      prune(clock);
      return { key, log: true, count: 1, suppressed: 0 };
    }
    state.count += 1;
    total += 1;
    if (state.count <= maxPerKey) {
      return { key, log: true, count: state.count, suppressed: 0 };
    }
    suppressed += 1;
    state.suppressed = (state.suppressed || 0) + 1;
    return { key, log: false, count: state.count, suppressed: state.suppressed };
  }

  function summary() {
    const items = [];
    for (const [key, state] of states) {
      items.push({
        key,
        count: state.count,
        suppressed: state.suppressed || 0,
        windowStart: state.windowStart,
      });
    }
    items.sort((left, right) => right.count - left.count || left.key.localeCompare(right.key));
    return { entries: items, total, suppressed, keys: states.size, windowMs, maxPerKey };
  }

  function reset() {
    states.clear();
    suppressed = 0;
    total = 0;
  }

  return { record, summary, reset, windowMs, maxPerKey, maxKeys };
}

module.exports = {
  DEFAULT_WINDOW_MS,
  DEFAULT_MAX_PER_KEY,
  DEFAULT_MAX_KEYS,
  normalizeKey,
  createDenyLedger,
};
