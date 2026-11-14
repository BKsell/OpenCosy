'use strict';

const STATE = {
  PENDING: 'pending',
  PROGRESS: 'progressing',
  PAUSED: 'paused',
  COMPLETED: 'completed',
  CANCELLED: 'cancelled',
  INTERRUPTED: 'interrupted'
};

const ACTION = {
  PAUSE: 'pause',
  RESUME: 'resume',
  CANCEL: 'cancel',
  RETRY: 'retry',
  OPEN: 'open',
  REVEAL: 'reveal'
};

const TRANSITIONS = {
  [STATE.PENDING]: { [ACTION.CANCEL]: STATE.CANCELLED },
  [STATE.PROGRESS]: { [ACTION.PAUSE]: STATE.PAUSED, [ACTION.CANCEL]: STATE.CANCELLED },
  [STATE.PAUSED]: { [ACTION.RESUME]: STATE.PROGRESS, [ACTION.CANCEL]: STATE.CANCELLED },
  [STATE.INTERRUPTED]: { [ACTION.RETRY]: STATE.PENDING, [ACTION.CANCEL]: STATE.CANCELLED },
  [STATE.COMPLETED]: { [ACTION.OPEN]: STATE.COMPLETED, [ACTION.REVEAL]: STATE.COMPLETED },
  [STATE.CANCELLED]: {}
};

const REASON = {
  OK: 'ok',
  UNKNOWN_STATE: 'unknown-state',
  UNKNOWN_ACTION: 'unknown-action',
  NOT_ALLOWED: 'not-allowed',
  NO_RECEIVED: 'no-received-bytes',
  MALFORMED: 'malformed'
};

function normalizeState(state) {
  return Object.prototype.hasOwnProperty.call(TRANSITIONS, state) ? state : null;
}

function normalizeAction(action) {
  return Object.prototype.hasOwnProperty.call(ACTION, Object.keys(ACTION).find((k) => ACTION[k] === action) || '') ? action : null;
}

function allowedActions(state) {
  const normalized = normalizeState(state);
  if (!normalized) return [];
  return Object.keys(TRANSITIONS[normalized]);
}

function canTransition(state, action) {
  const normalized = normalizeState(state);
  if (!normalized) return { ok: false, reason: REASON.UNKNOWN_STATE };
  if (!normalizeAction(action)) return { ok: false, reason: REASON.UNKNOWN_ACTION };
  const next = TRANSITIONS[normalized][action];
  if (!next) return { ok: false, reason: REASON.NOT_ALLOWED, state: normalized };
  return { ok: true, reason: REASON.OK, state: normalized, next };
}

function applyAction(item, action) {
  if (!item || typeof item !== 'object') return { ok: false, reason: REASON.MALFORMED };
  const check = canTransition(item.state, action);
  if (!check.ok) return check;
  const updated = Object.assign({}, item, { state: check.next, updatedAt: Date.now() });
  if (action === ACTION.RESUME) {
    updated.error = null;
  }
  if (action === ACTION.CANCEL) {
    updated.speedBytesPerSecond = 0;
  }
  return { ok: true, reason: REASON.OK, state: check.next, item: updated };
}

function progressRatio(item) {
  if (!item || typeof item !== 'object') return 0;
  const total = Number(item.totalBytes);
  const received = Number(item.receivedBytes);
  if (!Number.isFinite(total) || !Number.isFinite(received) || total <= 0) return 0;
  return Math.min(1, Math.max(0, received / total));
}

function remainingSeconds(item) {
  if (!item || typeof item !== 'object') return null;
  const total = Number(item.totalBytes);
  const received = Number(item.receivedBytes);
  const speed = Number(item.speedBytesPerSecond);
  if (!Number.isFinite(total) || !Number.isFinite(received) || !Number.isFinite(speed) || speed <= 0) return null;
  const left = total - received;
  if (left <= 0) return 0;
  return Math.ceil(left / speed);
}

function describeState(state) {
  switch (state) {
    case STATE.PENDING: return '等待开始';
    case STATE.PROGRESS: return '下载中';
    case STATE.PAUSED: return '已暂停';
    case STATE.COMPLETED: return '已完成';
    case STATE.CANCELLED: return '已取消';
    case STATE.INTERRUPTED: return '已中断';
    default: return '未知状态';
  }
}

function summarizeItem(item) {
  if (!item || typeof item !== 'object') return { ok: false, reason: REASON.MALFORMED };
  const ratio = progressRatio(item);
  const eta = remainingSeconds(item);
  const percent = Math.floor(ratio * 100);
  const parts = [describeState(item.state)];
  if (Number(item.totalBytes) > 0) parts.push(percent + '%');
  if (eta !== null && eta > 0) parts.push('剩余 ' + eta + ' 秒');
  return {
    ok: true,
    reason: REASON.OK,
    state: item.state,
    ratio,
    percent,
    etaSeconds: eta,
    text: parts.join(' · '),
    actions: allowedActions(item.state)
  };
}

function mergeProgress(item, payload) {
  if (!item || typeof item !== 'object' || !payload || typeof payload !== 'object') {
    return { ok: false, reason: REASON.MALFORMED };
  }
  const next = Object.assign({}, item, {
    receivedBytes: Number.isFinite(Number(payload.receivedBytes)) ? Number(payload.receivedBytes) : item.receivedBytes,
    totalBytes: Number.isFinite(Number(payload.totalBytes)) ? Number(payload.totalBytes) : item.totalBytes,
    speedBytesPerSecond: Number.isFinite(Number(payload.speedBytesPerSecond)) ? Number(payload.speedBytesPerSecond) : item.speedBytesPerSecond,
    updatedAt: Date.now()
  });
  if (!Number.isFinite(Number(next.receivedBytes)) || Number(next.receivedBytes) < 0) {
    return { ok: false, reason: REASON.NO_RECEIVED };
  }
  return { ok: true, reason: REASON.OK, item: next };
}

module.exports = {
  STATE,
  ACTION,
  REASON,
  allowedActions,
  canTransition,
  applyAction,
  progressRatio,
  remainingSeconds,
  describeState,
  summarizeItem,
  mergeProgress
};
