'use strict';

const REASON = {
  PROTOCOL_SCHEME_UNKNOWN: 'protocol-scheme-unknown',
  PROTOCOL_AUTO_ALLOW_RISK: 'protocol-auto-allow-risk',
  PROTOCOL_HANDLER_NOT_HTTPS: 'protocol-handler-not-https',
  PROTOCOL_SCHEME_LIMIT: 'protocol-scheme-limit',
};

const LIMITS = {
  MAX_SCHEMES: 5,
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

function evaluateProtocolHandlerConfirmGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const protocol_scheme_unknownList = Array.isArray(pick(data, 'schemes')) ? pick(data, 'schemes') : [];
  const protocol_scheme_unknownHit = protocol_scheme_unknownList.some((item) => !['webcal', 'mailto', 'tel'].includes(String((item && typeof item === 'object' ? item : item) || '').toLowerCase()));
  if (protocol_scheme_unknownHit) {
    add(REASON.PROTOCOL_SCHEME_UNKNOWN, '协议处理器注册了未知 scheme', true);
  }

  if (pick(data, 'autoAllow') === true) {
    add(REASON.PROTOCOL_AUTO_ALLOW_RISK, '自动放行外部协议会跳过确认', true);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'handlerUrl')))) {
    add(REASON.PROTOCOL_HANDLER_NOT_HTTPS, '协议处理器地址不是 HTTPS', true);
  }

  const protocol_scheme_limitList = Array.isArray(pick(data, 'schemes')) ? pick(data, 'schemes') : [];
  if (protocol_scheme_limitList.length > 5) {
    add(REASON.PROTOCOL_SCHEME_LIMIT, '协议处理器数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeProtocolHandlerConfirmGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateProtocolHandlerConfirmGuard, describeProtocolHandlerConfirmGuard };
