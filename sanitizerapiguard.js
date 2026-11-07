'use strict';

const REASON = {
  SANITIZER_NAMESPACE: 'sanitizer-namespace',
  SANITIZER_ELEMENT_WILDCARD: 'sanitizer-element-wildcard',
  SANITIZER_SCRIPT_ELEMENT: 'sanitizer-script-element',
  SANITIZER_ATTRIBUTE_WILDCARD: 'sanitizer-attribute-wildcard',
  SANITIZER_ELEMENT_LIMIT: 'sanitizer-element-limit',
  SANITIZER_ATTRIBUTE_LIMIT: 'sanitizer-attribute-limit',
};

const LIMITS = {
  MAX_ELEMENTS: 40,
  MAX_ATTRIBUTES: 20,
};

function pick(source, path) {
  let current = source;
  for (const part of path.split('.')) {
    if (!current || typeof current !== 'object') return undefined;
    current = current[part];
  }
  return current;
}

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function evaluateSanitizerApiGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!['default'].includes(text(pick(data, 'namespace')).toLowerCase())) {
    add(REASON.SANITIZER_NAMESPACE, 'Sanitizer 命名空间必须是 default', true);
  }

  const sanitizer_element_wildcardList = Array.isArray(pick(data, 'elements')) ? pick(data, 'elements') : [];
  const sanitizer_element_wildcardHit = sanitizer_element_wildcardList.some((item) => String((item && typeof item === 'object' ? item : item) || '').toLowerCase() === '*');
  if (sanitizer_element_wildcardHit) {
    add(REASON.SANITIZER_ELEMENT_WILDCARD, '元素白名单不允许通配符', true);
  }

  const sanitizer_script_elementList = Array.isArray(pick(data, 'elements')) ? pick(data, 'elements') : [];
  const sanitizer_script_elementHit = sanitizer_script_elementList.some((item) => String((item && typeof item === 'object' ? item : item) || '').toLowerCase() === 'script');
  if (sanitizer_script_elementHit) {
    add(REASON.SANITIZER_SCRIPT_ELEMENT, '元素白名单包含可执行标签', true);
  }

  const sanitizer_attribute_wildcardList = Array.isArray(pick(data, 'attributes')) ? pick(data, 'attributes') : [];
  const sanitizer_attribute_wildcardHit = sanitizer_attribute_wildcardList.some((item) => String((item && typeof item === 'object' ? item : item) || '').toLowerCase() === '*');
  if (sanitizer_attribute_wildcardHit) {
    add(REASON.SANITIZER_ATTRIBUTE_WILDCARD, '属性白名单不允许通配符', false);
  }

  const sanitizer_element_limitList = Array.isArray(pick(data, 'elements')) ? pick(data, 'elements') : [];
  if (sanitizer_element_limitList.length > 40) {
    add(REASON.SANITIZER_ELEMENT_LIMIT, '元素白名单数量超出上限', false);
  }

  const sanitizer_attribute_limitList = Array.isArray(pick(data, 'attributes')) ? pick(data, 'attributes') : [];
  if (sanitizer_attribute_limitList.length > 20) {
    add(REASON.SANITIZER_ATTRIBUTE_LIMIT, '属性白名单数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeSanitizerApiGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateSanitizerApiGuard, describeSanitizerApiGuard };
