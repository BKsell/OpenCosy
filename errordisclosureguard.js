'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'error-body-empty',
  STACK_TRACE: 'error-stack-trace',
  SQL_LEAK: 'error-sql-leak',
  ABSOLUTE_PATH: 'error-absolute-path',
  DEBUG_FLAG: 'error-debug-flag',
  SECRET_TOKEN: 'error-secret-token',
};

const SQL_HINTS = ['select ', 'insert into', 'update ', 'delete from', 'syntax error at or near', 'ora-0', 'sqlstate'];
const PATH_HINTS = ['/home/', '/var/www', 'c:\\users', '/usr/local', '/opt/'];
const DEBUG_HINTS = ['traceback (most recent call last)', 'goroutine ', 'at java.', 'stack trace', 'whoops'];
const SECRET_HINTS = ['api_key=', 'apikey=', 'password=', 'secret=', 'token=', 'authorization:'];

function evaluateErrorBody(status, body, options) {
  const opts = options || {};
  const text = typeof body === 'string' ? body : '';
  if (text.trim() === '') {
    return { ok: true, blocked: false, reason: REASON.EMPTY, findings: [] };
  }
  const findings = [];
  const lower = text.toLowerCase();
  for (const hint of DEBUG_HINTS) {
    if (lower.includes(hint)) findings.push({ reason: REASON.DEBUG_FLAG, hint });
  }
  for (const hint of SQL_HINTS) {
    if (lower.includes(hint)) {
      findings.push({ reason: REASON.SQL_LEAK, hint });
      break;
    }
  }
  for (const hint of PATH_HINTS) {
    if (lower.includes(hint)) {
      findings.push({ reason: REASON.ABSOLUTE_PATH, hint });
      break;
    }
  }
  for (const hint of SECRET_HINTS) {
    if (lower.includes(hint)) {
      findings.push({ reason: REASON.SECRET_TOKEN, hint });
      break;
    }
  }
  if (/at [a-z0-9_.]+\([^)]*:[0-9]+\)/i.test(text)) {
    findings.push({ reason: REASON.STACK_TRACE, hint: 'frame' });
  }
  if (findings.length > 0) {
    const blocked = opts.strict === true || status >= 500;
    return { ok: false, blocked, reason: findings[0].reason, findings, status: Number(status) || 0 };
  }
  return { ok: true, blocked: false, reason: REASON.OK, findings: [] };
}

function redactBody(body, options) {
  const opts = options || {};
  let text = typeof body === 'string' ? body : '';
  if (text === '') return '';
  if (opts.maxBytes && text.length > opts.maxBytes) text = text.slice(0, opts.maxBytes);
  text = text
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/g, '[email]')
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '[ip]');
  return text;
}

module.exports = {
  REASON,
  SQL_HINTS,
  PATH_HINTS,
  DEBUG_HINTS,
  SECRET_HINTS,
  evaluateErrorBody,
  redactBody,
};
