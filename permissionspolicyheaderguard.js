'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'policy-header-empty',
  MISSING_DIRECTIVE: 'policy-directive-missing',
  WILDCARD: 'policy-wildcard',
  SELF_OVERRIDE: 'policy-self-wildcard',
};

const REQUIRED = ['geolocation', 'camera', 'microphone', 'payment'];
const OPTIONAL = ['usb', 'serial', 'hid', 'bluetooth', 'speaker-selection'];

function parsePolicy(header) {
  const text = typeof header === 'string' ? header : '';
  if (text.trim() === '') return [];
  return text
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
    .map((entry) => {
      const eq = entry.indexOf('=');
      const name = (eq === -1 ? entry : entry.slice(0, eq)).trim().toLowerCase();
      const tail = eq === -1 ? '' : entry.slice(eq + 1);
      const values = tail
        .split(/\s+/)
        .map((part) => part.replace(/[;"'()]/g, '').toLowerCase())
        .filter((part) => part !== '');
      return { name, values };
    });
}

function evaluatePermissionsPolicy(header, options) {
  const opts = options || {};
  const entries = parsePolicy(header);
  if (entries.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, findings: [] };
  }
  const required = Array.isArray(opts.required) ? opts.required.map((item) => item.toLowerCase()) : REQUIRED;
  const optional = Array.isArray(opts.optional) ? opts.optional.map((item) => item.toLowerCase()) : OPTIONAL;
  const byName = new Map();
  for (const entry of entries) byName.set(entry.name, entry);
  const findings = [];
  for (const directive of required) {
    if (!byName.has(directive)) {
      findings.push({ reason: REASON.MISSING_DIRECTIVE, directive });
      continue;
    }
    const entry = byName.get(directive);
    if (entry.values.includes('*')) findings.push({ reason: REASON.WILDCARD, directive });
    if (directive === 'geolocation' && opts.denySelfGeolocation === false && entry.values.includes('self')) {
      findings.push({ reason: REASON.SELF_OVERRIDE, directive });
    }
  }
  for (const directive of optional) {
    const entry = byName.get(directive);
    if (entry && entry.values.includes('*')) findings.push({ reason: REASON.WILDCARD, directive });
  }
  if (findings.length > 0) {
    return { ok: false, blocked: findings.some((f) => f.reason === REASON.WILDCARD), reason: findings[0].reason, findings };
  }
  return { ok: true, blocked: false, reason: REASON.OK, findings: [] };
}

function buildDenyAll(directives) {
  const list = Array.isArray(directives) && directives.length > 0 ? directives : REQUIRED.concat(OPTIONAL);
  return list.map((name) => name + '=()').join(', ');
}

module.exports = {
  REASON,
  REQUIRED,
  OPTIONAL,
  parsePolicy,
  evaluatePermissionsPolicy,
  buildDenyAll,
};
