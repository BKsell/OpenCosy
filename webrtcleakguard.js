'use strict';

const REASON = {
  OK: 'ok',
  IP_EXPOSED: 'webrtc-ip-exposure',
  POLICY_BLOCKED: 'webrtc-policy-blocked',
  NO_PERMISSION: 'webrtc-permission-missing',
  CROSS_ORIGIN: 'cross-origin-webrtc',
};

const ICE_POLICIES = new Set(['default', 'relay', 'all', 'none', 'disable']);

function normalizePolicy(value) {
  const policy = String(value || '').toLowerCase();
  if (policy === 'disable' || policy === 'none') return 'disable';
  if (policy === 'relay') return 'relay';
  if (policy === 'all') return 'all';
  return 'default';
}

function localCandidateTypes(value) {
  const types = new Set();
  const text = String(value || '');
  for (const line of text.split('\n')) {
    const m = line.match(/typ\s+([a-z]+)/i);
    if (m) types.add(m[1].toLowerCase());
  }
  return types;
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const policy = normalizePolicy(req.policy);
  if (policy === 'disable') return { blocked: true, reason: REASON.POLICY_BLOCKED, policy };
  if (!req.userPermission) return { blocked: true, reason: REASON.NO_PERMISSION, policy };
  if (req.allowCrossOrigin !== true && req.topOrigin && req.origin && req.topOrigin !== req.origin) {
    return { blocked: true, reason: REASON.CROSS_ORIGIN, policy };
  }
  if (policy === 'all') return { blocked: true, reason: REASON.IP_EXPOSED, policy };
  const types = localCandidateTypes(req.sdp);
  if (policy !== 'relay' && (types.has('host') || types.has('srflx'))) {
    return { blocked: true, reason: REASON.IP_EXPOSED, policy, candidateTypes: Array.from(types) };
  }
  return { blocked: false, reason: REASON.OK, policy };
}

function applyWebRtcLeakGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  const constraints = {
    iceTransportPolicy: result.policy === 'relay' ? 'relay' : result.blocked ? 'none' : 'all',
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require',
  };
  return {
    blocked: result.blocked,
    reason: result.reason,
    policy: result.policy,
    constraints,
    candidateTypes: result.candidateTypes || [],
  };
}

function auditWebRtcBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.blocked) blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ origin: item && item.origin, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no webrtc leak risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyWebRtcLeakGuard,
  auditWebRtcBatch,
  describeFindings,
  normalizePolicy,
};
