'use strict';

const diskSpace = require('./downloaddiskspace');

const DEFAULT_NOTIFY_INTERVAL_MS = 60 * 1000;
const DEFAULT_RESUME_RATIO = 1.5;
const MAX_TRACKED_IDS = 512;

const ACTION = Object.freeze({
  CONTINUE: 'continue',
  PAUSE: 'pause',
  RESUME: 'resume',
  BLOCK: 'block',
  SKIP: 'skip',
});

const REASON = Object.freeze({
  OK: 'ok',
  LOW_FREE: 'low-free',
  RESUME_READY: 'resume-ready',
  INVALID_SAMPLE: 'invalid-sample',
  UNKNOWN_ID: 'unknown-id',
  THROTTLED: 'throttled',
  UNREQUIRED: 'unrequired',
});

function createDiskMonitor(options) {
  const config = options && typeof options === 'object' ? options : {};
  const minFreeBytes = diskSpace.safeBytes(config.minFreeBytes) || diskSpace.MIN_FREE_BYTES;
  const resumeRatio = Number.isFinite(Number(config.resumeRatio)) && Number(config.resumeRatio) >= 1
    ? Number(config.resumeRatio)
    : DEFAULT_RESUME_RATIO;
  const resumeFreeBytes = diskSpace.safeBytes(config.resumeFreeBytes) || Math.ceil(minFreeBytes * resumeRatio);
  const notifyIntervalMs = Number.isFinite(Number(config.notifyIntervalMs)) && Number(config.notifyIntervalMs) >= 0
    ? Math.floor(Number(config.notifyIntervalMs))
    : DEFAULT_NOTIFY_INTERVAL_MS;
  const now = typeof config.now === 'function' ? config.now : Date.now;
  const downloads = new Map();
  let lastFreeBytes = null;
  let lastSampleAt = 0;
  let pausedCount = 0;

  function track(id, totalBytes, receivedBytes) {
    const key = typeof id === 'string' && id.length > 0 ? id : '';
    if (!key) return null;
    if (!downloads.has(key) && downloads.size >= MAX_TRACKED_IDS) {
      const oldest = downloads.keys().next();
      if (!oldest.done) {
        const entry = downloads.get(oldest.value);
        if (entry && entry.paused) pausedCount -= 1;
        downloads.delete(oldest.value);
      }
    }
    const previous = downloads.get(key) || { paused: false, notified: false, notifiedAt: 0, totalBytes: 0, receivedBytes: 0 };
    const record = {
      paused: previous.paused,
      notified: previous.notified,
      notifiedAt: previous.notifiedAt,
      totalBytes: diskSpace.safeBytes(totalBytes) || previous.totalBytes,
      receivedBytes: diskSpace.safeBytes(receivedBytes) || previous.receivedBytes,
    };
    downloads.set(key, record);
    return record;
  }

  function sample(input) {
    const source = input && typeof input === 'object' ? input : {};
    const freeBytes = Number(source.freeBytes);
    const id = typeof source.id === 'string' ? source.id : '';
    if (!Number.isFinite(freeBytes) || freeBytes < 0) {
      return { action: ACTION.SKIP, id, reason: REASON.INVALID_SAMPLE, freeBytes: lastFreeBytes };
    }
    lastFreeBytes = diskSpace.safeBytes(freeBytes);
    lastSampleAt = now();
    const record = track(id, source.totalBytes, source.receivedBytes);
    if (!record) {
      return { action: ACTION.SKIP, id, reason: REASON.UNKNOWN_ID, freeBytes: lastFreeBytes };
    }
    const decision = diskSpace.evaluateProgress({
      freeBytes: lastFreeBytes,
      totalBytes: record.totalBytes,
      receivedBytes: record.receivedBytes,
    });
    if (decision.action === diskSpace.PROGRESS.PAUSE) {
      if (record.paused) {
        return { action: ACTION.SKIP, id, reason: REASON.THROTTLED, freeBytes: lastFreeBytes, decision };
      }
      record.paused = true;
      pausedCount += 1;
      record.notified = false;
      record.notifiedAt = lastSampleAt;
      return { action: ACTION.PAUSE, id, reason: REASON.LOW_FREE, freeBytes: lastFreeBytes, decision };
    }
    if (!record.paused) {
      return { action: ACTION.CONTINUE, id, reason: REASON.OK, freeBytes: lastFreeBytes, decision };
    }
    if (lastFreeBytes < resumeFreeBytes) {
      return { action: ACTION.SKIP, id, reason: REASON.LOW_FREE, freeBytes: lastFreeBytes, decision };
    }
    record.paused = false;
    pausedCount -= 1;
    return { action: ACTION.RESUME, id, reason: REASON.RESUME_READY, freeBytes: lastFreeBytes, decision };
  }

  function release(id) {
    const key = typeof id === 'string' ? id : '';
    const record = downloads.get(key);
    if (!record) return false;
    if (record.paused) pausedCount -= 1;
    downloads.delete(key);
    return true;
  }

  function reset() {
    downloads.clear();
    pausedCount = 0;
    lastFreeBytes = null;
    lastSampleAt = 0;
  }

  function snapshot() {
    return {
      tracked: downloads.size,
      paused: pausedCount,
      freeBytes: lastFreeBytes,
      sampledAt: lastSampleAt,
      minFreeBytes,
      resumeFreeBytes,
      notifyIntervalMs,
    };
  }

  function shouldNotify(id) {
    const record = downloads.get(typeof id === 'string' ? id : '');
    if (!record) return false;
    if (!record.notified) return true;
    return now() - record.notifiedAt >= notifyIntervalMs;
  }

  function markNotified(id) {
    const record = downloads.get(typeof id === 'string' ? id : '');
    if (!record) return false;
    record.notified = true;
    record.notifiedAt = now();
    return true;
  }

  return {
    sample,
    release,
    reset,
    snapshot,
    shouldNotify,
    markNotified,
    minFreeBytes,
    resumeFreeBytes,
  };
}

function describeMonitorEvent(event) {
  if (!event || typeof event !== 'object') return '磁盘监视事件缺失';
  switch (event.action) {
    case ACTION.PAUSE:
      return `下载 ${event.id} 已因磁盘空间不足暂停`;
    case ACTION.RESUME:
      return `下载 ${event.id} 的磁盘空间已恢复，可继续`;
    case ACTION.BLOCK:
      return `下载 ${event.id} 因磁盘空间判定被拒绝`;
    case ACTION.CONTINUE:
      return `下载 ${event.id} 磁盘空间充足`;
    case ACTION.SKIP:
      return `下载 ${event.id} 无需处理（${event.reason}）`;
    default:
      return `未知磁盘监视动作：${String(event.action || '')}`;
  }
}

module.exports = {
  DEFAULT_NOTIFY_INTERVAL_MS,
  DEFAULT_RESUME_RATIO,
  MAX_TRACKED_IDS,
  ACTION,
  REASON,
  createDiskMonitor,
  describeMonitorEvent,
};
