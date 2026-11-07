'use strict';

const REASON = {
  DEVTOOLS_ENABLED_RISK: 'devtools-enabled-risk',
  DEVTOOLS_PORT_RANGE: 'devtools-port-range',
  DEVTOOLS_PUBLIC_BIND: 'devtools-public-bind',
  DEVTOOLS_TOKEN_SHORT: 'devtools-token-short',
};

const LIMITS = {
  MIN_PORT: 1024,
  MAX_PORT: 65535,
  MIN_TOKEN: 24,
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

function evaluateDevtoolsRemoteGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'enabled') === true) {
    add(REASON.DEVTOOLS_ENABLED_RISK, '远程调试端口处于开启状态', true);
  }

  const devtools_port_rangeValue = Number(pick(data, 'port'));
  if (Number.isFinite(devtools_port_rangeValue) && (devtools_port_rangeValue < 1024 || devtools_port_rangeValue > 65535)) {
    add(REASON.DEVTOOLS_PORT_RANGE, '调试端口超出非特权区间', false);
  }

  if (new RegExp('^(?!127\\.|::1$|localhost)').test(text(pick(data, 'bind')))) {
    add(REASON.DEVTOOLS_PUBLIC_BIND, '调试端口绑定到非回环地址', true);
  }

  const devtools_token_shortValue = Number(pick(data, 'tokenLength'));
  if (Number.isFinite(devtools_token_shortValue) && (devtools_token_shortValue < 0 || devtools_token_shortValue > 23)) {
    add(REASON.DEVTOOLS_TOKEN_SHORT, '调试访问令牌过短', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeDevtoolsRemoteGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateDevtoolsRemoteGuard, describeDevtoolsRemoteGuard };
