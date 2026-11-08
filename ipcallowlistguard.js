'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'channel-empty',
  TOO_LONG: 'channel-too-long',
  WILDCARD: 'channel-wildcard',
  NOT_ALLOWED: 'channel-not-allowed',
  SENSITIVE_PREFIX: 'channel-sensitive-prefix',
  CONTROL_CHARS: 'channel-control-chars',
};

const MAX_CHANNEL = 128;
const CONTROL = /[\u0000-\u001f\u007f]/;
const SENSITIVE = ['internal:', 'debug:', 'shell:', 'admin:', 'update:'];

function normalizeChannel(value) {
  return String(value || '').trim();
}

function matchPattern(channel, pattern) {
  if (typeof pattern !== 'string') return false;
  if (pattern.endsWith('*')) {
    return channel.startsWith(pattern.slice(0, -1));
  }
  return channel === pattern;
}

function evaluateChannel(channel, options) {
  const opts = options || {};
  const allowlist = Array.isArray(opts.allowlist) ? opts.allowlist : [];
  const name = normalizeChannel(channel);
  if (name === '') return { ok: false, blocked: true, reason: REASON.EMPTY, channel: name };
  if (name.length > MAX_CHANNEL) return { ok: false, blocked: true, reason: REASON.TOO_LONG, channel: name };
  if (CONTROL.test(name)) return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, channel: name };
  if (name.includes('*') || name.includes('?')) {
    return { ok: false, blocked: true, reason: REASON.WILDCARD, channel: name };
  }
  for (const prefix of SENSITIVE) {
    if (name.toLowerCase().startsWith(prefix)) {
      return { ok: false, blocked: true, reason: REASON.SENSITIVE_PREFIX, channel: name };
    }
    }
  const allowed = allowlist.some((pattern) => matchPattern(name, pattern));
  if (!allowed) return { ok: false, blocked: true, reason: REASON.NOT_ALLOWED, channel: name };
  return { ok: true, blocked: false, reason: REASON.OK, channel: name };
}

function evaluateIpcRequest(request, options) {
  const req = request || {};
  const result = evaluateChannel(req.channel, options);
  if (result.blocked) return { ...result, sender: req.sender || null };
  if (req.senderFrameUrl) {
    let url;
    try {
      url = new URL(String(req.senderFrameUrl));
    } catch (err) {
      return { ok: false, blocked: true, reason: REASON.NOT_ALLOWED, channel: result.channel, sender: req.senderFrameUrl };
    }
    const local = url.protocol === 'file:' || url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (!local && url.protocol !== 'https:') {
      return { ok: false, blocked: true, reason: REASON.NOT_ALLOWED, channel: result.channel, sender: url.href };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, channel: result.channel };
}

function auditIpcBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateIpcRequest(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ channel: result.channel, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no ipc channel risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.channel || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateChannel,
  evaluateIpcRequest,
  auditIpcBatch,
  describeFindings,
};
