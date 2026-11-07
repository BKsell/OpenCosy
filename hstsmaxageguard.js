'use strict';

const LIMITS = {"maxItems": 32, "maxLength": 512};

const RULES = [
  { key: "HSTSAGE_FLAG_OFF", message: "HSTS 有效期必需开关未开启", blocking: true, kind: "value-boolean-true", path: "hsts.enabled", extra: null },
  { key: "HSTSAGE_REPORT_ONLY", message: "HSTS 有效期仍处于仅观察模式", blocking: false, kind: "value-boolean-false", path: "hsts.reportOnly", extra: null },
  { key: "HSTSAGE_MODE_INVALID", message: "HSTS 有效期强度档位不在允许集合", blocking: true, kind: "text-enum", path: "hsts.mode", extra: ["strict", "standard"] },
  { key: "HSTSAGE_COUNT_OUT_OF_RANGE", message: "HSTS 有效期有效期设置超出安全区间", blocking: false, kind: "value-range", path: "hsts.lifetime", extra: [31536000, 63072000] },
  { key: "HSTSAGE_ENDPOINT_INSECURE", message: "HSTS 有效期端点不是合法的 HTTPS 地址", blocking: true, kind: "text-pattern", path: "hsts.endpoint", extra: "^https://[a-z0-9._/-]+$" },
  { key: "HSTSAGE_ENDPOINT_TOO_LONG", message: "HSTS 有效期端点长度超出上限", blocking: false, kind: "text-too-long", path: "hsts.endpoint", extra: 512 },
  { key: "HSTSAGE_NOTE_CONTROL", message: "HSTS 有效期备注含控制字符", blocking: false, kind: "text-control", path: "hsts.note", extra: null },
  { key: "HSTSAGE_PATH_TRAVERSAL", message: "HSTS 有效期路径配置允许目录上跳", blocking: true, kind: "text-traversal", path: "hsts.storagePath", extra: null },
  { key: "HSTSAGE_ITEM_UNKNOWN", message: "HSTS 有效期条目不在白名单内", blocking: true, kind: "list-item-equals", path: "hsts.items", extra: ["includeSubDomains", "preload"] },
  { key: "HSTSAGE_ITEM_DUPLICATE", message: "HSTS 有效期白名单存在重复条目", blocking: false, kind: "list-duplicate", path: "hsts.items", extra: null },
  { key: "HSTSAGE_ITEM_COUNT", message: "HSTS 有效期白名单条目过多", blocking: false, kind: "list-count", path: "hsts.items", extra: 6 },
  { key: "HSTSAGE_BASELINE_EMPTY", message: "HSTS 有效期基线列表为空", blocking: false, kind: "list-empty", path: "hsts.baseline", extra: null },
];

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function pickPath(snapshot, path) {
  const parts = path.split('.');
  let cursor = snapshot;
  for (const part of parts) {
    if (!isPlainObject(cursor)) {
      return undefined;
    }
    if (!(part in cursor)) {
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

function boolValue(value) {
  if (value === true || value === 'true') {
    return true;
  }
  if (value === false || value === 'false') {
    return false;
  }
  return undefined;
}

function asText(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return '';
}

function checkBooleanTrue(value) {
  const parsed = boolValue(value);
  if (parsed === undefined) {
    return '不是布尔值: ' + describeType(value);
  }
  if (!parsed) {
    return '期望 true';
  }
  return '';
}

function checkBooleanFalse(value) {
  const parsed = boolValue(value);
  if (parsed === undefined) {
    return '不是布尔值: ' + describeType(value);
  }
  if (parsed) {
    return '期望 false';
  }
  return '';
}

function checkRange(value, extra) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return '不是有效数字: ' + describeType(value);
  }
  const low = extra[0];
  const high = extra[1];
  if (value < low || value > high) {
    return '取值 ' + value + ' 不在 ' + low + '..' + high + ' 内';
  }
  return '';
}

function checkEnum(value, extra) {
  const text = asText(value).trim().toLowerCase();
  if (text === '') {
    return '为空';
  }
  if (!extra.includes(text)) {
    return '不在允许集合: ' + text;
  }
  return '';
}

function checkPattern(value, extra) {
  const text = asText(value);
  if (typeof value !== 'string') {
    return '不是字符串: ' + describeType(value);
  }
  if (!new RegExp(extra).test(text)) {
    return '不匹配白名单表达式';
  }
  return '';
}

function checkTooLong(value, extra, limits) {
  const text = asText(value);
  const max = extra === null ? limits.maxLength : extra;
  if (text.length > max) {
    return '长度 ' + text.length + ' 超过上限 ' + max;
  }
  return '';
}

function checkControl(value) {
  const text = asText(value);
  for (const char of text) {
    const code = char.codePointAt(0);
    if (code < 0x20 || code === 0x7f) {
      return '含控制字符 U+' + code.toString(16).toUpperCase();
    }
  }
  return '';
}

function checkTraversal(value) {
  const text = asText(value);
  if (text.includes('..')) {
    return '含上跳片段';
  }
  if (text.includes('\\')) {
    return '含反斜杠分隔符';
  }
  if (text.startsWith('/')) {
    return '使用绝对路径';
  }
  return '';
}

function checkList(value) {
  if (!Array.isArray(value)) {
    return '不是数组: ' + describeType(value);
  }
  return '';
}

function lowerItems(value) {
  return value
    .filter((item) => typeof item === 'string')
    .map((item) => item.trim().toLowerCase());
}

function checkListEmpty(value) {
  const basic = checkList(value);
  if (basic) {
    return basic;
  }
  if (value.length === 0) {
    return '为空数组';
  }
  return '';
}

function checkListCount(value, extra, limits) {
  const basic = checkList(value);
  if (basic) {
    return basic;
  }
  const max = extra === null ? limits.maxItems : extra;
  if (value.length > max) {
    return '条目数 ' + value.length + ' 超过上限 ' + max;
  }
  return '';
}

function checkListDuplicate(value) {
  const basic = checkList(value);
  if (basic) {
    return basic;
  }
  const seen = new Set();
  for (const item of lowerItems(value)) {
    if (seen.has(item)) {
      return '重复条目: ' + item;
    }
    seen.add(item);
  }
  return '';
}

function checkItemEquals(value, extra) {
  const basic = checkList(value);
  if (basic) {
    return basic;
  }
  const allowed = extra.map((item) => item.toLowerCase());
  for (const item of value) {
    if (typeof item !== 'string') {
      return '条目不是字符串: ' + describeType(item);
    }
    if (!allowed.includes(item.trim().toLowerCase())) {
      return '条目不在允许集合: ' + item;
    }
  }
  return '';
}

function checkRule(rule, value, limits) {
  switch (rule.kind) {
    case 'value-boolean-true':
      return checkBooleanTrue(value);
    case 'value-boolean-false':
      return checkBooleanFalse(value);
    case 'value-range':
      return checkRange(value, rule.extra);
    case 'text-enum':
      return checkEnum(value, rule.extra);
    case 'text-pattern':
      return checkPattern(value, rule.extra);
    case 'text-too-long':
      return checkTooLong(value, rule.extra, limits);
    case 'text-control':
      return checkControl(value);
    case 'text-traversal':
      return checkTraversal(value);
    case 'list-empty':
      return checkListEmpty(value);
    case 'list-count':
      return checkListCount(value, rule.extra, limits);
    case 'list-duplicate':
      return checkListDuplicate(value);
    case 'list-item-equals':
      return checkItemEquals(value, rule.extra);
    default:
      return '未知规则类型: ' + rule.kind;
  }
}

function finishHstsmaxage(findings) {
  return {
    module: 'hstsmaxageguard',
    ok: findings.length === 0,
    findings,
  };
}

function evaluateHstsmaxageGuard(snapshot) {
  const findings = [];
  if (!isPlainObject(snapshot)) {
    findings.push({
      key: 'SNAPSHOT_INVALID',
      message: '快照不是对象，无法校验 hstsmaxageguard 配置',
      blocking: true,
    });
    return finishHstsmaxage(findings);
  }
  for (const rule of RULES) {
    const value = pickPath(snapshot, rule.path);
    const detail = checkRule(rule, value, LIMITS);
    if (detail) {
      findings.push({
        key: rule.key,
        message: rule.message + ' (' + detail + ')',
        blocking: rule.blocking,
      });
    }
  }
  return finishHstsmaxage(findings);
}

function describeHstsmaxageGuard(result) {
  if (!result || !Array.isArray(result.findings)) {
    return 'hstsmaxageguard: invalid result';
  }
  if (result.findings.length === 0) {
    return 'hstsmaxageguard: ok';
  }
  const parts = result.findings.map((finding) => {
    const level = finding.blocking ? '[block]' : '[warn]';
    return level + ' ' + finding.key + ' ' + finding.message;
  });
  return 'hstsmaxageguard: ' + parts.join('; ');
}

module.exports = {
  RULES,
  LIMITS,
  evaluateHstsmaxageGuard,
  describeHstsmaxageGuard,
};
