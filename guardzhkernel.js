'use strict';

const LIMITS = { maxItems: 32, maxLength: 512 };

const RULE_SPECS = [
  { suffix: 'FLAG_OFF', message: '策略开关未开启', blocking: true, kind: 'value-boolean-true', path: 'enabled', extra: null },
  { suffix: 'REPORT_ONLY', message: '处于仅报告模式', blocking: false, kind: 'value-boolean-false', path: 'reportOnly', extra: null },
  { suffix: 'MODE_INVALID', message: '执行模式不在允许集合', blocking: true, kind: 'text-enum', path: 'mode', extra: ['enforce', 'report'] },
  { suffix: 'COUNT_OUT_OF_RANGE', message: '条目上限超出允许区间', blocking: false, kind: 'value-range', path: 'maxItems', extra: [1, 32] },
  { suffix: 'ENDPOINT_INSECURE', message: '上报端点非 HTTPS', blocking: true, kind: 'text-pattern', path: 'endpoint', extra: '^https://[a-z0-9._/-]+$' },
  { suffix: 'ENDPOINT_TOO_LONG', message: '上报端点超长', blocking: false, kind: 'text-too-long', path: 'endpoint', extra: 100 },
  { suffix: 'NOTE_CONTROL', message: '说明字段含控制字符', blocking: false, kind: 'text-control', path: 'note', extra: null },
  { suffix: 'PATH_TRAVERSAL', message: '回退路径含穿越片段', blocking: true, kind: 'text-traversal', path: 'fallbackPath', extra: null },
  { suffix: 'ITEM_UNKNOWN', message: '条目不在允许集合', blocking: true, kind: 'list-item-equals', path: 'items', extra: ['default-src', 'script-src', 'style-src', 'img-src', 'connect-src', 'frame-src'] },
  { suffix: 'ITEM_DUPLICATE', message: '条目重复', blocking: false, kind: 'list-duplicate', path: 'items', extra: null },
  { suffix: 'ITEM_COUNT', message: '条目数量超出上限', blocking: false, kind: 'list-count', path: 'items', extra: 12 },
  { suffix: 'BASELINE_EMPTY', message: '基线集合为空', blocking: false, kind: 'list-empty', path: 'baseline', extra: null },
  { suffix: 'ORIGIN_UNKNOWN', message: '来源不在允许集合', blocking: false, kind: 'list-item-equals', path: 'origins', extra: ['self', 'https://example.com'] },
];

function buildRules(prefix) {
  const rules = [];
  for (const spec of RULE_SPECS) {
    const rule = {
      key: prefix + '_' + spec.suffix,
      message: spec.message,
      blocking: spec.blocking,
      kind: spec.kind,
      path: spec.path,
    };
    if (spec.extra !== null) {
      rule.extra = spec.extra;
    }
    rules.push(rule);
  }
  return rules;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isInteger(value) {
  return typeof value === 'number' && Number.isInteger(value);
}

function pickPath(source, path) {
  if (!isPlainObject(source)) {
    return undefined;
  }
  const parts = path.split('.');
  let cursor = source;
  for (const part of parts) {
    if (!isPlainObject(cursor)) {
      return undefined;
    }
    cursor = cursor[part];
  }
  return cursor;
}

function describeType(value) {
  if (value === undefined) {
    return 'missing';
  }
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  return typeof value;
}

function asText(value) {
  return typeof value === 'string' ? value : '';
}

function checkBooleanTrue(value) {
  return value === true;
}

function checkBooleanFalse(value) {
  return value === false;
}

function checkRange(value, extra) {
  if (!isInteger(value)) {
    return false;
  }
  return value >= extra[0] && value <= extra[1];
}

function checkEnum(value, extra) {
  if (typeof value !== 'string') {
    return false;
  }
  return extra.indexOf(value) !== -1;
}

function checkPattern(value, extra) {
  if (typeof value !== 'string') {
    return false;
  }
  try {
    return new RegExp(extra).test(value);
  } catch (err) {
    return false;
  }
}

function checkTooLong(value, extra) {
  if (typeof value !== 'string') {
    return false;
  }
  return value.length <= extra;
}

function checkControl(value) {
  if (typeof value !== 'string') {
    return false;
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return false;
    }
  }
  return true;
}

function checkTraversal(value) {
  if (typeof value !== 'string') {
    return false;
  }
  if (value.indexOf('..') !== -1) {
    return false;
  }
  if (value.indexOf('\\') !== -1) {
    return false;
  }
  return value.indexOf('/') !== 0;
}

function checkListEmpty(value) {
  return Array.isArray(value) && value.length > 0;
}

function checkListCount(value, extra) {
  if (!Array.isArray(value)) {
    return false;
  }
  return value.length <= extra;
}

function checkListDuplicate(value) {
  if (!Array.isArray(value)) {
    return false;
  }
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== 'string') {
      return false;
    }
    if (seen.has(item)) {
      return false;
    }
    seen.add(item);
  }
  return true;
}

function checkItemEquals(value, extra) {
  if (!Array.isArray(value)) {
    return false;
  }
  for (const item of value) {
    if (typeof item !== 'string') {
      return false;
    }
    if (extra.indexOf(item) === -1) {
      return false;
    }
  }
  return true;
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

function ruleFinding(rule, value) {
  return {
    key: rule.key,
    message: rule.message + '（实际类型 ' + describeType(value) + '）',
    path: rule.path,
    blocking: rule.blocking === true,
  };
}

function makeZhGuard(options) {
  const prefix = options.prefix;
  const label = options.label;
  const rules = buildRules(prefix);

  function evaluate(policy) {
    if (!isPlainObject(policy)) {
      return {
        ok: false,
        blocking: true,
        findings: [
          {
            key: prefix + '_CONFIG_INVALID',
            message: '策略配置必须是普通对象',
            path: '',
            blocking: true,
          },
        ],
      };
    }
    const findings = [];
    for (const rule of rules) {
      const value = pickPath(policy, rule.path);
      const check = KIND_CHECKS[rule.kind];
      const passed = typeof check === 'function' ? check(value, rule.extra) : false;
      if (!passed) {
        findings.push(ruleFinding(rule, value));
      }
    }
    const blocking = findings.some((item) => item.blocking === true);
    return { ok: findings.length === 0, blocking, findings };
  }

  function summarize(policy) {
    const result = evaluate(policy);
    let blocking = 0;
    let advisory = 0;
    for (const item of result.findings) {
      if (item.blocking) {
        blocking += 1;
      } else {
        advisory += 1;
      }
    }
    return {
      ok: result.ok,
      total: result.findings.length,
      blocking,
      advisory,
      keys: result.findings.map((item) => item.key),
    };
  }

  function describe(policy) {
    const result = evaluate(policy);
    if (result.ok) {
      return label + '：策略配置未发现风险';
    }
    const parts = [];
    for (let i = 0; i < result.findings.length; i += 1) {
      if (i >= 10) {
        parts.push('…共 ' + result.findings.length + ' 项');
        break;
      }
      const item = result.findings[i];
      parts.push(item.key + '(' + asText(item.path) + ')');
    }
    return label + '：' + parts.join('；');
  }

  return { LIMITS, RULES: rules, evaluate, summarize, describe };
}

module.exports = { LIMITS, makeZhGuard };
