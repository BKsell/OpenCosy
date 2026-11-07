'use strict';

const REASON = {
  OK: 'ok',
  NO_ORIGIN: 'origin-missing',
  INSECURE: 'insecure-origin',
  DEVICE_ENUMERATION: 'device-enumeration',
  UNKNOWN_DEVICE: 'unknown-device',
  AUDIO_ONLY_DOWNGRADE: 'audio-only-downgrade',
  PERSISTED_DEVICE: 'persisted-device-id',
};

const SAFE_KINDS = new Set(['audioinput', 'videoinput']);

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const origin = parse(req.origin);
  if (!origin) return { allowed: false, reason: REASON.NO_ORIGIN, constraints: {} };
  if (origin.protocol !== 'https:' && req.allowInsecure !== true) {
    return { allowed: false, reason: REASON.INSECURE, constraints: {} };
  }
  const kinds = Array.isArray(req.kinds) ? req.kinds.map((k) => String(k).toLowerCase()) : [];
  const unsafe = kinds.filter((k) => !SAFE_KINDS.has(k));
  if (unsafe.length > 0) return { allowed: false, reason: REASON.UNKNOWN_DEVICE, constraints: {}, kinds: unsafe };
  if (req.enumerateDevices) return { allowed: false, reason: REASON.DEVICE_ENUMERATION, constraints: {} };
  if (typeof req.deviceId === 'string' && req.deviceId.length > 0 && req.persistDeviceId) {
    return { allowed: false, reason: REASON.PERSISTED_DEVICE, constraints: {} };
  }
  const constraints = {};
  const audio = kinds.includes('audioinput');
  const video = kinds.includes('videoinput');
  if (audio) constraints.audio = { echoCancellation: true, noiseSuppression: true, autoGainControl: true };
  if (video) constraints.video = { width: { max: 1280 }, height: { max: 720 }, frameRate: { max: 30 } };
  return { allowed: true, reason: req.audioOnly ? REASON.AUDIO_ONLY_DOWNGRADE : REASON.OK, constraints };
}

function applyMediaDeviceGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  return {
    allowed: result.allowed,
    reason: result.reason,
    constraints: result.constraints,
    kinds: result.kinds || [],
  };
}

function auditMediaBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let denied = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (!result.allowed) denied += 1;
    if (result.reason !== REASON.OK) findings.push({ origin: item && item.origin, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { denied, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no media device risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyMediaDeviceGuard,
  auditMediaBatch,
  describeFindings,
};
