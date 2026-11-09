'use strict';

// 外部协议确认的节流内核：页面可以反复调用 open-external-url，
// 每次都会弹一个原生确认框。恶意页面靠高频弹窗既能把用户逼成"手快点了同意"，
// 也能把系统对话框当成 UI 劫持手段。这里按 origin + scheme 做滑动窗口限流，
// 并对同一 URL 的短时间重复做去重。

const DEFAULT_WINDOW_MS = 60000;
const DEFAULT_MAX_PER_WINDOW = 3;
const DUPLICATE_WINDOW_MS = 2000;
const MAX_TRACKED_KEYS = 512;

function createLimiter(options) {
  const opts = options || {};
  const windowMs = Number(opts.windowMs) > 0 ? Number(opts.windowMs) : DEFAULT_WINDOW_MS;
  const maxPerWindow = Number(opts.maxPerWindow) > 0 ? Number(opts.maxPerWindow) : DEFAULT_MAX_PER_WINDOW;
  const duplicateWindowMs = Number(opts.duplicateWindowMs) >= 0 ? Number(opts.duplicateWindowMs) : DUPLICATE_WINDOW_MS;
  return { windowMs, maxPerWindow, duplicateWindowMs, buckets: new Map(), lastUrl: new Map() };
}

function prune(times, now, windowMs) {
  let i = 0;
  while (i < times.length && now - times[i] >= windowMs) i += 1;
  return i > 0 ? times.slice(i) : times;
}

function sweep(limiter, now) {
  for (const [key, times] of limiter.buckets) {
    const kept = prune(times, now, limiter.windowMs);
    if (kept.length === 0) limiter.buckets.delete(key);
    else if (kept !== times) limiter.buckets.set(key, kept);
  }
  for (const [key, rec] of limiter.lastUrl) {
    if (now - rec.at >= limiter.windowMs) limiter.lastUrl.delete(key);
  }
}

function check(limiter, origin, scheme, url, now) {
  const t = Number.isFinite(Number(now)) ? Number(now) : Date.now();
  if (limiter.buckets.size >= MAX_TRACKED_KEYS) sweep(limiter, t);
  if (limiter.buckets.size >= MAX_TRACKED_KEYS) {
    const oldest = limiter.buckets.keys().next();
    if (!oldest.done) limiter.buckets.delete(oldest.value);
  }
  const key = String(origin || '') + '|' + String(scheme || '');
  const prevTimes = prune(limiter.buckets.get(key) || [], t, limiter.windowMs);

  if (url) {
    const last = limiter.lastUrl.get(key);
    if (last && last.url === url && t - last.at < limiter.duplicateWindowMs) {
      return { ok: false, reason: 'duplicate', retryAfterMs: limiter.duplicateWindowMs - (t - last.at) };
    }
  }

  if (prevTimes.length >= limiter.maxPerWindow) {
    const oldest = prevTimes[0];
    return { ok: false, reason: 'rate-limited', retryAfterMs: limiter.windowMs - (t - oldest) };
  }

  const nextTimes = prevTimes.concat([t]);
  limiter.buckets.set(key, nextTimes);
  if (url) limiter.lastUrl.set(key, { url, at: t });
  return { ok: true, reason: '', retryAfterMs: 0 };
}

function describeReason(reason) {
  if (reason === 'duplicate') return '重复的协议唤起请求';
  if (reason === 'rate-limited') return '外部协议唤起过于频繁';
  return '';
}

module.exports = { createLimiter, check, sweep, describeReason };
