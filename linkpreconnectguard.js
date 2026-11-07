'use strict';

const LIMITS = { maxItems: 32, maxLength: 512 };

const RULES = [
  { key: 'LINKPRECO_FLAG_OFF', message: "guard must stay enabled", blocking: true, kind: 'boolean-true', path: 'enabled', extra: null },
  { key: 'LINKPRECO_REPORT_ONLY', message: "reportOnly must be false for enforcement", blocking: false, kind: 'boolean-false', path: 'reportOnly', extra: null },
  { key: 'LINKPRECO_MODE_INVALID', message: "mode is outside the supported set", blocking: true, kind: 'text-enum', path: 'mode', extra: ["enforce", "report-only"] },
  { key: 'LINKPRECO_COUNT_OUT_OF_RANGE', message: "maxItems is outside the accepted range", blocking: true, kind: 'value-range', path: 'maxItems', extra: [1, 32] },
  { key: 'LINKPRECO_ENDPOINT_INSECURE', message: "endpoint must use https", blocking: true, kind: 'text-pattern', path: 'endpoint', extra: "^https://[a-z0-9._/-]+$" },
  { key: 'LINKPRECO_ENDPOINT_TOO_LONG', message: "endpoint exceeds the length limit", blocking: false, kind: 'text-too-long', path: 'endpoint', extra: 512 },
  { key: 'LINKPRECO_NOTE_CONTROL', message: "note contains control characters", blocking: false, kind: 'text-control', path: 'note', extra: null },
  { key: 'LINKPRECO_PATH_TRAVERSAL', message: "fallbackPath escapes the root", blocking: true, kind: 'text-traversal', path: 'fallbackPath', extra: null },
  { key: 'LINKPRECO_ITEM_UNKNOWN', message: "items carry an unknown directive", blocking: true, kind: 'list-item-equals', path: 'items', extra: ["default-src", "script-src", "style-src", "img-src", "connect-src", "frame-src"] },
  { key: 'LINKPRECO_ITEM_DUPLICATE', message: "items repeat a directive", blocking: false, kind: 'list-duplicate', path: 'items', extra: null },
  { key: 'LINKPRECO_ITEM_COUNT', message: "items exceed the count limit", blocking: false, kind: 'list-count', path: 'items', extra: 32 },
  { key: 'LINKPRECO_BASELINE_EMPTY', message: "baseline must not be empty", blocking: true, kind: 'list-empty', path: 'baseline', extra: null },
  { key: 'LINKPRECO_ORIGIN_UNKNOWN', message: "origins carry an unknown source", blocking: true, kind: 'list-item-equals', path: 'origins', extra: ["self", "https://example.com"] },
];

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isInteger(value) {
  return typeof value === 'number' && Number.isInteger(value);
}

function pickPath(config, path) {
  const parts = path.split('.');
  let cursor = config;
  for (const part of parts) {
    if (!isPlainObject(cursor) || !(part in cursor)) {
      return undefined;
    }
    cursor = cursor[part];
  }
  return cursor;
}

function describeType(value) {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  return typeof value;
}

function asText(value) {
  return typeof value === 'string' ? value : '';
}

function checkBooleanTrue(value) {
  if (typeof value !== 'boolean') return 'expected boolean, got ' + describeType(value);
  return value ? null : 'expected true';
}

function checkBooleanFalse(value) {
  if (typeof value !== 'boolean') return 'expected boolean, got ' + describeType(value);
  return value ? 'expected false' : null;
}

function checkRange(value, extra) {
  if (!isInteger(value)) return 'expected integer, got ' + describeType(value);
  const low = extra[0];
  const high = extra[1];
  if (value < low || value > high) return 'expected ' + low + '..' + high + ', got ' + value;
  return null;
}

function checkEnum(value, extra) {
  const text = asText(value);
  if (text === '') return 'expected one of ' + extra.join('|');
  return extra.includes(text) ? null : 'unexpected value ' + text;
}

function checkPattern(value, extra) {
  const text = asText(value);
  if (text === '') return 'expected text';
  return new RegExp(extra).test(text) ? null : 'pattern mismatch';
}

function checkTooLong(value, extra) {
  const text = asText(value);
  if (text === '') return 'expected text';
  return text.length > extra ? 'length ' + text.length + ' over ' + extra : null;
}

function checkControl(value) {
  const text = asText(value);
  if (text === '') return 'expected text';
  return /[\u0000-\u001f\u007f]/.test(text) ? 'contains control characters' : null;
}

function checkTraversal(value) {
  const text = asText(value);
  if (text === '') return 'expected text';
  if (text.includes('..') || text.includes('\\') || text.startsWith('/')) return 'path escapes root';
  return null;
}

function checkListEmpty(value) {
  if (!Array.isArray(value)) return 'expected array, got ' + describeType(value);
  return value.length === 0 ? 'expected at least one entry' : null;
}

function checkListCount(value, extra) {
  if (!Array.isArray(value)) return 'expected array, got ' + describeType(value);
  return value.length > extra ? 'count ' + value.length + ' over ' + extra : null;
}

function checkListDuplicate(value) {
  if (!Array.isArray(value)) return 'expected array, got ' + describeType(value);
  const seen = new Set();
  for (const item of value) {
    const text = asText(item);
    if (seen.has(text)) return 'duplicate entry ' + text;
    seen.add(text);
  }
  return null;
}

function checkItemEquals(value, extra) {
  if (!Array.isArray(value)) return 'expected array, got ' + describeType(value);
  for (const item of value) {
    if (!extra.includes(asText(item))) return 'unknown entry ' + asText(item);
  }
  return null;
}

const KIND_CHECKS = {
  'boolean-true': (value) => checkBooleanTrue(value),
  'boolean-false': (value) => checkBooleanFalse(value),
  'value-range': (value, extra) => checkRange(value, extra),
  'text-enum': (value, extra) => checkEnum(value, extra),
  'text-pattern': (value, extra) => checkPattern(value, extra),
  'text-too-long': (value, extra) => checkTooLong(value, extra),
  'text-control': (value) => checkControl(value),
  'text-traversal': (value) => checkTraversal(value),
  'list-empty': (value) => checkListEmpty(value),
  'list-count': (value, extra) => checkListCount(value, extra),
  'list-duplicate': (value) => checkListDuplicate(value),
  'list-item-equals': (value, extra) => checkItemEquals(value, extra),
};

function ruleFinding(rule, reason) {
  return { key: rule.key, message: rule.message, reason: reason, blocking: rule.blocking };
}

function evaluateLinkpreconnectGuard(config) {
  if (!isPlainObject(config)) {
    return {
      ok: false,
      findings: [
        {
          key: 'LINKPRECO_CONFIG_INVALID',
          message: 'configuration must be a plain object',
          reason: 'expected object, got ' + describeType(config),
          blocking: true,
        },
      ],
    };
  }
  const findings = [];
  for (const rule of RULES) {
    const check = KIND_CHECKS[rule.kind];
    if (typeof check !== 'function') {
      findings.push({
        key: 'LINKPRECO_CONFIG_INVALID',
        message: 'rule kind is not supported',
        reason: rule.kind,
        blocking: true,
      });
      continue;
    }
    const value = pickPath(config, rule.path);
    const reason = check(value, rule.extra);
    if (reason) findings.push(ruleFinding(rule, reason));
  }
  return { ok: findings.length === 0, findings };
}

function summarizeLinkpreconnectGuard(config) {
  const result = evaluateLinkpreconnectGuard(config);
  const keys = result.findings.map((finding) => finding.key).sort();
  let blocking = 0;
  for (const finding of result.findings) {
    if (finding.blocking) blocking += 1;
  }
  return {
    ok: result.ok,
    total: result.findings.length,
    blocking: blocking,
    advisory: result.findings.length - blocking,
    keys: keys,
  };
}

function describeLinkpreconnectGuard(config) {
  const result = evaluateLinkpreconnectGuard(config);
  if (result.ok) return 'linkpreconnect 配置通过全部检查';
  const parts = [];
  for (const finding of result.findings) {
    if (parts.length >= 10) {
      parts.push('…等 ' + result.findings.length + ' 项');
      break;
    }
    parts.push(finding.key + ': ' + finding.message);
  }
  return parts.join('; ');
}

module.exports = { LIMITS, RULES, evaluateLinkpreconnectGuard, summarizeLinkpreconnectGuard, describeLinkpreconnectGuard };
