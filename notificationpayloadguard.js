'use strict';

const REASON = {
  OK: 'ok',
  EMPTY_TITLE: 'notification-empty-title',
  TOO_LONG: 'notification-too-long',
  MARKDOWN_INJECTION: 'notification-script-scheme',
  CONTROL_CHARS: 'notification-control-chars',
  ICON_REMOTE: 'notification-remote-icon',
  ACTION_URL: 'notification-action-url',
  ICON_DATA_URI: 'notification-data-uri-icon',
};

const MAX_TITLE = 256;
const MAX_BODY = 4096;

function evaluateNotification(payload, options) {
  const item = payload || {};
  const opts = options || {};
  const title = String(item.title || '');
  const body = String(item.body || '');
  if (title.trim() === '' && body.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY_TITLE, title };
  }
  if (title.length > MAX_TITLE || body.length > MAX_BODY) {
    return { ok: false, blocked: true, reason: REASON.TOO_LONG, title: title.slice(0, 64) };
  }
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(title + body)) {
    return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, title };
  }
  if (/(javascript:|vbscript:)/i.test(title + body)) {
    return { ok: false, blocked: true, reason: REASON.MARKDOWN_INJECTION, title };
  }
  if (item.icon) {
    const icon = String(item.icon);
    if (/^data:/i.test(icon)) return { ok: false, blocked: true, reason: REASON.ICON_DATA_URI, title };
    if (/^https?:/i.test(icon)) {
      let host = '';
      try {
        host = new URL(icon).hostname;
      } catch (err) {
        return { ok: false, blocked: true, reason: REASON.ICON_REMOTE, title };
      }
      if (!opts.iconHosts || !opts.iconHosts.includes(host)) {
        return { ok: false, blocked: true, reason: REASON.ICON_REMOTE, title, host };
      }
    }
  }
  if (item.actionUrl && !/^(file|https):/i.test(String(item.actionUrl))) {
    return { ok: false, blocked: true, reason: REASON.ACTION_URL, title };
  }
  return { ok: true, blocked: false, reason: REASON.OK, title, body };
}

function auditNotificationBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateNotification(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, title: result.title });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no notification risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.title || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateNotification,
  auditNotificationBatch,
  describeFindings,
};
