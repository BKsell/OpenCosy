'use strict';

const REASON = {
  OK: 'ok',
  INVALID_DISPLAY: 'window-display-invalid',
  INVALID_BOUNDS: 'window-bounds-invalid',
  ZERO_SIZE: 'window-zero-size',
  TOO_LARGE: 'window-too-large',
  OFFSCREEN: 'window-offscreen',
  MINIMIZED_OFFSCREEN: 'window-minimized-offscreen',
  TITLEBAR_HIDDEN: 'window-titlebar-hidden',
};

const MIN_WIDTH = 200;
const MIN_HEIGHT = 120;
const MAX_WIDTH = 16384;
const MAX_HEIGHT = 16384;
const TITLEBAR_HINT = 32;

function intersectionArea(a, b) {
  const left = Math.max(a.x, b.x);
  const top = Math.max(a.y, b.y);
  const right = Math.min(a.x + a.width, b.x + b.width);
  const bottom = Math.min(a.y + a.height, b.y + b.height);
  if (right <= left || bottom <= top) return 0;
  return (right - left) * (bottom - top);
}

function evaluateWindowBounds(bounds, displays) {
  const b = bounds || {};
  const list = Array.isArray(displays) ? displays : [];
  const width = Number(b.width);
  const height = Number(b.height);
  if (!Number.isFinite(width) || !Number.isFinite(height) || !Number.isFinite(Number(b.x)) || !Number.isFinite(Number(b.y))) {
    return { ok: false, blocked: true, reason: REASON.INVALID_BOUNDS, bounds: b };
  }
  if (width <= 0 || height <= 0) {
    return { ok: false, blocked: true, reason: REASON.ZERO_SIZE, width, height };
  }
  if (width > MAX_WIDTH || height > MAX_HEIGHT) {
    return { ok: false, blocked: true, reason: REASON.TOO_LARGE, width, height };
  }
  if (list.length === 0) {
    return { ok: false, blocked: true, reason: REASON.INVALID_DISPLAY, width, height };
  }
  let visible = 0;
  for (const display of list) {
    const workArea = display && display.workArea ? display.workArea : display;
    if (!workArea) continue;
    if (!Number.isFinite(Number(workArea.width)) || !Number.isFinite(Number(workArea.height))) continue;
    const area = intersectionArea(
      { x: Number(b.x), y: Number(b.y), width, height },
      { x: Number(workArea.x), y: Number(workArea.y), width: Number(workArea.width), height: Number(workArea.height) }
    );
    if (area > 0) visible += area;
  }
  const visibleRatio = visible / (width * height);
  if (b.minimized === true) {
    return { ok: true, blocked: false, reason: REASON.MINIMIZED_OFFSCREEN, visibleRatio };
  }
  if (visibleRatio < 0.2) {
    return { ok: false, blocked: true, reason: REASON.OFFSCREEN, visibleRatio: Math.round(visibleRatio * 100) / 100 };
  }
  if (b.titleBarHeight !== undefined && Number(b.titleBarHeight) < TITLEBAR_HINT) {
    return { ok: false, blocked: true, reason: REASON.TITLEBAR_HIDDEN, titleBarHeight: b.titleBarHeight };
  }
  if (width < MIN_WIDTH || height < MIN_HEIGHT) {
    return { ok: false, blocked: true, reason: REASON.INVALID_BOUNDS, width, height };
  }
  return { ok: true, blocked: false, reason: REASON.OK, visibleRatio: Math.round(visibleRatio * 100) / 100 };
}

function auditWindowBatch(list, displays) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateWindowBounds(item, displays);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, bounds: item });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no window bounds risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String((f.bounds && (f.bounds.x + ',' + f.bounds.y)) || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateWindowBounds,
  auditWindowBatch,
  describeFindings,
  intersectionArea,
};
