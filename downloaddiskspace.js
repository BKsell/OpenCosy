'use strict';

const MIN_FREE_BYTES = 512 * 1024 * 1024;
const LOW_FREE_BYTES = 256 * 1024 * 1024;
const RESERVE_RATIO = 0.15;
const MAX_RESERVE_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_NAME_BYTES = 240;

const ACTION = Object.freeze({
  ALLOW: 'allow',
  WARN: 'warn',
  BLOCK: 'block',
});

const PROGRESS = Object.freeze({
  CONTINUE: 'continue',
  PAUSE: 'pause',
});

const REASON = Object.freeze({
  OK: 'ok',
  INVALID: 'invalid',
  INSUFFICIENT: 'insufficient',
  LOW_FREE: 'low-free',
  UNKNOWN_SIZE: 'unknown-size',
  EXISTING_FILE: 'existing-file',
  PAUSED_LOW_FREE: 'paused-low-free',
  RECOVERED: 'recovered',
  NOT_TRACKED: 'not-tracked',
});

function safeBytes(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) return 0;
  if (num > Number.MAX_SAFE_INTEGER) return Number.MAX_SAFE_INTEGER;
  return Math.floor(num);
}

function requiredReserve(totalBytes) {
  const total = safeBytes(totalBytes);
  const proportional = Math.min(MAX_RESERVE_BYTES, Math.ceil(total * RESERVE_RATIO));
  return Math.max(MIN_FREE_BYTES, proportional);
}

function requiredFreeBytes(totalBytes) {
  return safeBytes(totalBytes) + requiredReserve(totalBytes);
}

function evaluateSpace(input) {
  const source = input && typeof input === 'object' ? input : {};
  const freeBytes = safeBytes(source.freeBytes);
  const totalBytes = safeBytes(source.totalBytes);
  const existingBytes = safeBytes(source.existingBytes);
  const required = requiredFreeBytes(totalBytes);
  if (!Number.isFinite(Number(source.freeBytes)) || Number(source.freeBytes) < 0) {
    return {
      action: ACTION.BLOCK, reason: REASON.INVALID, freeBytes: 0,
      totalBytes, requiredFreeBytes: required, shortfallBytes: required,
    };
  }
  if (totalBytes === 0) {
    if (freeBytes < MIN_FREE_BYTES) {
      return {
        action: ACTION.BLOCK, reason: REASON.LOW_FREE, freeBytes,
        totalBytes, requiredFreeBytes: MIN_FREE_BYTES, shortfallBytes: MIN_FREE_BYTES - freeBytes,
      };
    }
    return {
      action: ACTION.WARN, reason: REASON.UNKNOWN_SIZE, freeBytes,
      totalBytes, requiredFreeBytes: MIN_FREE_BYTES, shortfallBytes: 0,
    };
  }
  const need = safeBytes(totalBytes + existingBytes) + requiredReserve(totalBytes);
  if (freeBytes < need) {
    return {
      action: ACTION.BLOCK, reason: REASON.INSUFFICIENT, freeBytes, totalBytes,
      requiredFreeBytes: need, shortfallBytes: need - freeBytes,
    };
  }
  const remaining = freeBytes - totalBytes - existingBytes - requiredReserve(totalBytes);
  if (remaining < LOW_FREE_BYTES) {
    return {
      action: ACTION.WARN, reason: REASON.LOW_FREE, freeBytes, totalBytes,
      requiredFreeBytes: need, shortfallBytes: 0,
    };
  }
  return {
    action: ACTION.ALLOW, reason: REASON.OK, freeBytes, totalBytes,
    requiredFreeBytes: need, shortfallBytes: 0,
  };
}

function evaluateProgress(input) {
  const source = input && typeof input === 'object' ? input : {};
  const freeBytes = safeBytes(source.freeBytes);
  const totalBytes = safeBytes(source.totalBytes);
  const receivedBytes = safeBytes(source.receivedBytes);
  const remainingBytes = totalBytes > 0 ? Math.max(0, totalBytes - receivedBytes) : 0;
  const need = remainingBytes + requiredReserve(totalBytes || receivedBytes);
  if (!Number.isFinite(Number(source.freeBytes)) || freeBytes < need) {
    return {
      action: PROGRESS.PAUSE, reason: REASON.PAUSED_LOW_FREE,
      freeBytes, remainingBytes, requiredFreeBytes: need,
    };
  }
  return {
    action: PROGRESS.CONTINUE, reason: REASON.RECOVERED,
    freeBytes, remainingBytes, requiredFreeBytes: need,
  };
}

function planCleanup(input) {
  const source = input && typeof input === 'object' ? input : {};
  const freeBytes = safeBytes(source.freeBytes);
  const needBytes = safeBytes(source.needBytes);
  const candidates = Array.isArray(source.candidates) ? source.candidates : [];
  const plan = [];
  let projected = freeBytes;
  const sorted = candidates
    .filter((item) => item && safeBytes(item.size) > 0 && typeof item.path === 'string' && item.path.length > 0)
    .sort((left, right) => {
      const leftAt = Number(left.updatedAt) || 0;
      const rightAt = Number(right.updatedAt) || 0;
      if (leftAt === rightAt) return safeBytes(right.size) - safeBytes(left.size);
      return leftAt - rightAt;
    });
  for (const item of sorted) {
    if (projected >= needBytes) break;
    const size = safeBytes(item.size);
    plan.push({ path: item.path, size });
    projected += size;
  }
  return {
    ready: projected >= needBytes,
    projectedFreeBytes: projected,
    shortfallBytes: Math.max(0, needBytes - projected),
    entries: plan,
    freedBytes: plan.reduce((sum, entry) => sum + entry.size, 0),
  };
}

function describeDecision(decision) {
  if (!decision || typeof decision !== 'object') return '未知磁盘空间判定';
  const free = formatBytes(safeBytes(decision.freeBytes));
  switch (decision.reason) {
    case REASON.OK:
      return `磁盘剩余 ${free}，满足下载所需 ${formatBytes(safeBytes(decision.requiredFreeBytes))}`;
    case REASON.INSUFFICIENT:
      return `磁盘剩余 ${free}，不足以下载：还需 ${formatBytes(safeBytes(decision.shortfallBytes))}`;
    case REASON.LOW_FREE:
      return `磁盘剩余 ${free}，低于安全阈值 ${formatBytes(MIN_FREE_BYTES)}`;
    case REASON.UNKNOWN_SIZE:
      return '服务器未提供下载体积，仅在剩余空间低于安全阈值时拒绝';
    case REASON.INVALID:
      return '无法读取目标磁盘剩余空间';
    case REASON.PAUSED_LOW_FREE:
      return `下载已暂停：剩余 ${free}，续传还需 ${formatBytes(safeBytes(decision.requiredFreeBytes))}`;
    case REASON.RECOVERED:
      return '磁盘空间已恢复，可以继续下载';
    default:
      return `磁盘空间判定：${String(decision.reason || 'unknown')}`;
  }
}

function formatBytes(value) {
  const bytes = safeBytes(value);
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

function auditDiskReport(summary) {
  const source = summary && typeof summary === 'object' ? summary : {};
  const scanned = safeBytes(source.scanned);
  const failed = safeBytes(source.failed);
  const lowFree = safeBytes(source.lowFree);
  const reasons = [];
  if (failed > 0) reasons.push('scan-failed');
  if (lowFree > 0) reasons.push('low-free');
  if (scanned - failed - lowFree > 0) reasons.push('ok');
  return {
    total: scanned,
    ok: Math.max(0, scanned - failed - lowFree),
    lowFree,
    failed,
    healthy: failed === 0 && lowFree === 0,
    reasons,
  };
}

module.exports = {
  MIN_FREE_BYTES,
  LOW_FREE_BYTES,
  RESERVE_RATIO,
  MAX_RESERVE_BYTES,
  MAX_NAME_BYTES,
  ACTION,
  PROGRESS,
  REASON,
  safeBytes,
  requiredReserve,
  requiredFreeBytes,
  evaluateSpace,
  evaluateProgress,
  planCleanup,
  describeDecision,
  formatBytes,
  auditDiskReport,
};
