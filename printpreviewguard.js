'use strict';

const REASON = {
  PRINT_PATH_TRAVERSAL: 'print-path-traversal',
  PRINT_HEADER_LONG: 'print-header-long',
  PRINT_FOOTER_LONG: 'print-footer-long',
  PRINT_URL_REVEAL: 'print-url-reveal',
  PRINT_COPIES_RANGE: 'print-copies-range',
};

const LIMITS = {
  MAX_COPIES: 10,
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

function evaluatePrintPreviewGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (text(pick(data, 'savePath')).includes('..')) {
    add(REASON.PRINT_PATH_TRAVERSAL, '打印导出路径包含穿越', true);
  }

  if (text(pick(data, 'header')).length > 128) {
    add(REASON.PRINT_HEADER_LONG, '打印页眉长度超出上限', false);
  }

  if (text(pick(data, 'footer')).length > 128) {
    add(REASON.PRINT_FOOTER_LONG, '打印页脚长度超出上限', false);
  }

  if (pick(data, 'includeUrl') === true) {
    add(REASON.PRINT_URL_REVEAL, '打印页脚包含完整地址会泄露内部 URL', false);
  }

  const print_copies_rangeValue = Number(pick(data, 'maxCopies'));
  if (Number.isFinite(print_copies_rangeValue) && (print_copies_rangeValue < 1 || print_copies_rangeValue > 10)) {
    add(REASON.PRINT_COPIES_RANGE, '打印份数超出区间', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describePrintPreviewGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluatePrintPreviewGuard, describePrintPreviewGuard };
