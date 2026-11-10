'use strict';

function createUnlockLimiter(options) {
  const opts = options || {};
  const now = typeof opts.now === 'function' ? opts.now : Date.now;
  const maxFailures = Number.isInteger(opts.maxFailures) && opts.maxFailures > 0 ? opts.maxFailures : 5;
  const baseDelayMs = Number.isInteger(opts.baseDelayMs) && opts.baseDelayMs > 0 ? opts.baseDelayMs : 30000;
  const maxDelayMs = Number.isInteger(opts.maxDelayMs) && opts.maxDelayMs >= baseDelayMs ? opts.maxDelayMs : 900000;
  let failures = 0;
  let blockedUntil = 0;

  function delayFor(count) {
    if (count < maxFailures) return 0;
    const over = count - maxFailures;
    const mult = Math.pow(2, Math.min(over, 20));
    return Math.min(baseDelayMs * mult, maxDelayMs);
  }

  function check() {
    const t = now();
    if (blockedUntil > t) {
      return { ok: false, reason: 'locked-out', retryAfterMs: blockedUntil - t, failures };
    }
    return { ok: true };
  }

  function fail() {
    failures += 1;
    const delay = delayFor(failures);
    if (delay > 0) blockedUntil = now() + delay;
    return { failures, retryAfterMs: delay };
  }

  function reset() {
    failures = 0;
    blockedUntil = 0;
  }

  function snapshot() {
    return { failures, blockedUntil, lockedOut: blockedUntil > now() };
  }

  return { check, fail, reset, snapshot };
}

module.exports = { createUnlockLimiter };
