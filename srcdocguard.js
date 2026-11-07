'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'srcdoc-empty',
  SCRIPT_TAG: 'srcdoc-script',
  EVENT_HANDLER: 'srcdoc-event-handler',
  JAVASCRIPT_URL: 'srcdoc-javascript-url',
  EXTERNAL_FRAME: 'srcdoc-external-frame',
  DATA_ATTR_EXEC: 'srcdoc-exec-attr',
  OVERSIZED: 'srcdoc-oversized',
};

const EXEC_ATTRS = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onanimationstart'];
const MAX_SRCDOC = 65536;

function evaluateSrcdoc(html, options) {
  const opts = options || {};
  const text = typeof html === 'string' ? html : '';
  if (text.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, findings: [] };
  }
  if (text.length > (opts.maxBytes || MAX_SRCDOC)) {
    return { ok: false, blocked: true, reason: REASON.OVERSIZED, size: text.length, findings: [] };
  }
  const lower = text.toLowerCase();
  const findings = [];
  if (lower.includes('<script')) findings.push({ reason: REASON.SCRIPT_TAG });
  if (lower.includes('javascript:')) findings.push({ reason: REASON.JAVASCRIPT_URL });
  if (lower.includes('<iframe') && (lower.includes('src="http') || lower.includes("src='http"))) {
    findings.push({ reason: REASON.EXTERNAL_FRAME });
  }
  for (const attr of EXEC_ATTRS) {
    if (lower.includes(attr + '=') || lower.includes(attr + ' =')) {
      findings.push({ reason: REASON.EVENT_HANDLER, attr });
      break;
    }
  }
  for (const attr of ['src', 'href', 'action', 'formaction']) {
    const pattern = attr + '=';
    let index = lower.indexOf(pattern);
    while (index !== -1) {
      const rest = lower.slice(index + pattern.length, index + pattern.length + 20);
      if (rest.includes('data:')) findings.push({ reason: REASON.DATA_ATTR_EXEC, attr });
      index = lower.indexOf(pattern, index + 1);
    }
  }
  if (findings.length > 0) {
    return { ok: false, blocked: true, reason: findings[0].reason, findings };
  }
  return { ok: true, blocked: false, reason: REASON.OK, findings: [] };
}

function sandboxAttributes(options) {
  const opts = options || {};
  const base = ['allow-scripts'];
  if (opts.allowForms === true) base.push('allow-forms');
  if (opts.allowPopups === true) base.push('allow-popups');
  return base.join(' ');
}

module.exports = {
  REASON,
  EXEC_ATTRS,
  MAX_SRCDOC,
  evaluateSrcdoc,
  sandboxAttributes,
};
