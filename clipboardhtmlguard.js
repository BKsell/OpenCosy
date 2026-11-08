'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'clipboard-empty',
  TOO_LARGE: 'clipboard-too-large',
  HTML_PRESENT: 'clipboard-html',
  SCRIPT_CONTENT: 'clipboard-script',
  EVENT_HANDLER: 'clipboard-event-handler',
  DATA_URI: 'clipboard-data-uri',
  HIDDEN_CONTENT: 'clipboard-hidden-content',
  CONTROL_CHARS: 'clipboard-control-chars',
};

const MAX_TEXT = 4 * 1024 * 1024;

function evaluateClipboard(payload, options) {
  const item = payload || {};
  const opts = options || {};
  const text = typeof item.text === 'string' ? item.text : '';
  const html = typeof item.html === 'string' ? item.html : '';
  if (text.length === 0 && html.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, text: '' };
  }
  if (text.length + html.length > MAX_TEXT) {
    return { ok: false, blocked: true, reason: REASON.TOO_LARGE, size: text.length + html.length };
  }
  if (html.length > 0) {
    if (opts.allowHtml !== true) {
      return { ok: true, blocked: false, reason: REASON.HTML_PRESENT, text, stripHtml: true };
    }
    if (/<\s*script/i.test(html)) return { ok: false, blocked: true, reason: REASON.SCRIPT_CONTENT, text };
    if (/\son[a-z]+\s*=/i.test(html)) return { ok: false, blocked: true, reason: REASON.EVENT_HANDLER, text };
    if (/data:\s*text\/html/i.test(html)) return { ok: false, blocked: true, reason: REASON.DATA_URI, text };
    if (/display:\s*none|visibility:\s*hidden|opacity:\s*0/i.test(html)) {
      return { ok: false, blocked: true, reason: REASON.HIDDEN_CONTENT, text };
    }
  }
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text)) {
    return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, text };
  }
  return { ok: true, blocked: false, reason: REASON.OK, text, html: '' };
}

function evaluateClipboardWrite(request) {
  const req = request || {};
  const result = evaluateClipboard({ text: req.text, html: req.html }, req);
  if (result.blocked) return result;
  if (req.richText === true && req.trustedOrigin !== true) {
    return { ok: false, blocked: true, reason: REASON.HTML_PRESENT, text: result.text };
  }
  return result;
}

function auditClipboardBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateClipboardWrite(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, size: result.size });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no clipboard risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.size || 0) + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateClipboard,
  evaluateClipboardWrite,
  auditClipboardBatch,
  describeFindings,
};
