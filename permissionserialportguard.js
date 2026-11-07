'use strict';

const LIMITS = {
  maxItems: 32,
  maxLength: 512,
};

const RULES = [
  {
    key: 'PERMISSIO_FLAG_OFF',
    message: 'Permissions-Policy serial enforcement flag is disabled',
    blocking: true,
    kind: 'value-boolean-true',
    path: 'policy.enabled',
  },
  {
    key: 'PERMISSIO_REPORT_ONLY',
    message: 'Permissions-Policy serial is running in report-only mode',
    blocking: false,
    kind: 'value-boolean-false',
    path: 'policy.reportOnly',
  },
  {
    key: 'PERMISSIO_MODE_INVALID',
    message: 'Permissions-Policy serial mode is outside the supported set',
    blocking: true,
    kind: 'text-enum',
    path: 'policy.mode',
    extra: ['enforce', 'report'],
  },
  {
    key: 'PERMISSIO_COUNT_OUT_OF_RANGE',
    message: 'Permissions-Policy serial item budget is outside 1..32',
    blocking: false,
    kind: 'value-range',
    path: 'policy.maxItems',
    extra: [1, 32],
  },
  {
    key: 'PERMISSIO_ENDPOINT_INSECURE',
    message: 'Permissions-Policy serial report endpoint is not https',
    blocking: true,
    kind: 'text-pattern',
    path: 'policy.endpoint',
    extra: '^https://[a-z0-9._/-]+$',
  },
  {
    key: 'PERMISSIO_ENDPOINT_TOO_LONG',
    message: 'Permissions-Policy serial report endpoint exceeds the length budget',
    blocking: false,
    kind: 'text-too-long',
    path: 'policy.endpoint',
    extra: LIMITS.maxLength,
  },
  {
    key: 'PERMISSIO_NOTE_CONTROL',
    message: 'Permissions-Policy serial note contains control characters',
    blocking: false,
    kind: 'text-control',
    path: 'policy.note',
  },
  {
    key: 'PERMISSIO_PATH_TRAVERSAL',
    message: 'Permissions-Policy serial fallback path escapes the document root',
    blocking: true,
    kind: 'text-traversal',
    path: 'policy.fallbackPath',
  },
  {
    key: 'PERMISSIO_ITEM_UNKNOWN',
    message: 'Permissions-Policy serial declares an unknown source expression',
    blocking: true,
    kind: 'list-item-equals',
    path: 'policy.items',
    extra: ['default-src', 'script-src', 'style-src', 'img-src'],
  },
  {
    key: 'PERMISSIO_ITEM_DUPLICATE',
    message: 'Permissions-Policy serial declares duplicate source expressions',
    blocking: false,
    kind: 'list-duplicate',
    path: 'policy.items',
  },
  {
    key: 'PERMISSIO_ITEM_COUNT',
    message: 'Permissions-Policy serial declares more source expressions than allowed',
    blocking: false,
    kind: 'list-count',
    path: 'policy.items',
    extra: 16,
  },
  {
    key: 'PERMISSIO_BASELINE_EMPTY',
    message: 'Permissions-Policy serial baseline allowlist is empty',
    blocking: false,
    kind: 'list-empty',
    path: 'policy.baseline',
  },
];

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function pickPath(source, path) {
  if (!isPlainObject(source)) {
    return undefined;
  }
  const parts = path.split('.');
  let node = source;
  for (const part of parts) {
    if (!isPlainObject(node)) {
      return undefined;
    }
    if (!Object.prototype.hasOwnProperty.call(node, part)) {
      return undefined;
    }
    node = node[part];
  }
  return node;
}

function describeType(value) {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  return typeof value;
}

function boolValue(value) {
  if (value === true || value === false) {
    return value;
  }
  if (typeof value === 'string') {
    const lowered = value.trim().toLowerCase();
    if (lowered === 'true') {
      return true;
    }
    if (lowered === 'false') {
      return false;
    }
  }
  return null;
}

function asText(value) {
  if (typeof value === 'string') {
    return value;
  }
  return null;
}

function checkBooleanTrue(value) {
  if (boolValue(value) === true) {
    return null;
  }
  return 'expected true, got ' + describeType(value);
}

function checkBooleanFalse(value) {
  if (boolValue(value) === false) {
    return null;
  }
  return 'expected false, got ' + describeType(value);
}

function checkRange(value, extra) {
  const bounds = Array.isArray(extra) ? extra : [0, 0];
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    return 'expected integer, got ' + describeType(value);
  }
  if (value < bounds[0] || value > bounds[1]) {
    return 'value ' + value + ' outside ' + bounds[0] + '..' + bounds[1];
  }
  return null;
}

function checkEnum(value, extra) {
  const allow = Array.isArray(extra) ? extra : [];
  const text = asText(value);
  if (text === null) {
    return 'expected string, got ' + describeType(value);
  }
  if (!allow.includes(text)) {
    return 'value ' + text + ' not in allowlist';
  }
  return null;
}

function checkPattern(value, extra) {
  const text = asText(value);
  if (text === null) {
    return 'expected string, got ' + describeType(value);
  }
  let regexp = null;
  try {
    regexp = new RegExp(extra);
  } catch (error) {
    return 'invalid pattern in rule definition';
  }
  if (!regexp.test(text)) {
    return 'value does not match the required pattern';
  }
  return null;
}

function checkTooLong(value, extra) {
  const text = asText(value);
  if (text === null) {
    return 'expected string, got ' + describeType(value);
  }
  const limit = typeof extra === 'number' ? extra : LIMITS.maxLength;
  if (text.length > limit) {
    return 'length ' + text.length + ' exceeds ' + limit;
  }
  return null;
}

function checkControl(value) {
  const text = asText(value);
  if (text === null) {
    return 'expected string, got ' + describeType(value);
  }
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) {
      return 'control character at offset ' + index;
    }
  }
  return null;
}

function checkTraversal(value) {
  const text = asText(value);
  if (text === null) {
    return 'expected string, got ' + describeType(value);
  }
  const normalized = text.replace(/\\/g, '/');
  if (normalized.split('/').includes('..')) {
    return 'path segment ".." is not allowed';
  }
  if (normalized.startsWith('/')) {
    return 'absolute path is not allowed';
  }
  return null;
}

function checkList(value) {
  if (!Array.isArray(value)) {
    return null;
  }
  return value;
}

function lowerItems(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => (typeof item === 'string' ? item.trim().toLowerCase() : item));
}

function checkListEmpty(value) {
  const list = checkList(value);
  if (list === null) {
    return 'expected array, got ' + describeType(value);
  }
  if (list.length === 0) {
    return 'list must not be empty';
  }
  return null;
}

function checkListCount(value, extra) {
  const list = checkList(value);
  if (list === null) {
    return 'expected array, got ' + describeType(value);
  }
  const limit = typeof extra === 'number' ? extra : LIMITS.maxItems;
  if (list.length > limit) {
    return 'count ' + list.length + ' exceeds ' + limit;
  }
  return null;
}

function checkListDuplicate(value) {
  const list = lowerItems(value);
  const seen = new Set();
  for (const item of list) {
    if (seen.has(item)) {
      return 'duplicate entry ' + String(item);
    }
    seen.add(item);
  }
  return null;
}

function checkItemEquals(value, extra) {
  if (!Array.isArray(value)) {
    return 'expected array, got ' + describeType(value);
  }
  const allow = Array.isArray(extra) ? extra : [];
  for (const item of value) {
    const text = typeof item === 'string' ? item.trim().toLowerCase() : null;
    if (text === null) {
      return 'non-string entry of type ' + describeType(item);
    }
    if (!allow.includes(text)) {
      return 'entry ' + text + ' is not in the allowlist';
    }
  }
  return null;
}

const KIND_CHECKS = {
  'value-boolean-true': checkBooleanTrue,
  'value-boolean-false': checkBooleanFalse,
  'value-range': checkRange,
  'text-enum': checkEnum,
  'text-pattern': checkPattern,
  'text-too-long': checkTooLong,
  'text-control': checkControl,
  'text-traversal': checkTraversal,
  'list-empty': checkListEmpty,
  'list-count': checkListCount,
  'list-duplicate': checkListDuplicate,
  'list-item-equals': checkItemEquals,
};

function checkRule(rule, value) {
  if (value === undefined) {
    return {
      key: rule.key,
      message: rule.message,
      blocking: rule.blocking,
      detail: 'missing value',
    };
  }
  const checker = KIND_CHECKS[rule.kind];
  if (!checker) {
    return {
      key: rule.key,
      message: rule.message,
      blocking: rule.blocking,
      detail: 'unknown rule kind ' + rule.kind,
    };
  }
  const detail = checker(value, rule.extra);
  if (detail === null) {
    return null;
  }
  return {
    key: rule.key,
    message: rule.message,
    blocking: rule.blocking,
    detail,
  };
}

function finishPermissionserialportGuard(config) {
  const findings = [];
  if (config !== undefined && config !== null && typeof config !== 'object') {
    findings.push({
      key: 'PERMISSIO_CONFIG_INVALID',
      message: 'Permissions-Policy serial configuration must be an object',
      blocking: true,
      detail: 'got ' + describeType(config),
    });
  }
  for (const rule of RULES) {
    const value = pickPath(config, rule.path);
    const finding = checkRule(rule, value);
    if (finding) {
      findings.push(finding);
    }
  }
  const blocking = findings.some((finding) => finding.blocking);
  return {
    valid: findings.length === 0,
    blocking,
    findings,
    reasonCodes: findings.map((finding) => finding.key),
  };
}

function evaluatePermissionserialportGuard(config) {
  return finishPermissionserialportGuard(config);
}

function describePermissionserialportGuard(config) {
  const result = finishPermissionserialportGuard(config);
  if (result.valid) {
    return 'Permissions-Policy serial 配置满足基线要求';
  }
  return result.findings
    .map((finding) => finding.key + ':' + finding.detail)
    .join('; ');
}

module.exports = {
  RULES,
  LIMITS,
  evaluatePermissionserialportGuard,
  describePermissionserialportGuard,
};
