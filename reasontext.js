function describeReasonFrom(table, reason, fallback) {
  return Object.prototype.hasOwnProperty.call(table, reason) ? table[reason] : fallback;
}

function describeReasonTable(table, fallback) {
  return function describeReason(reason) {
    return describeReasonFrom(table, reason, fallback);
  };
}

function describeAuditResult(result, okText) {
  if (!result || result.reason === 'ok') return okText;
  return `${result.reason}: ${result.detail || ''}`.trim();
}

module.exports = { describeReasonFrom, describeReasonTable, describeAuditResult };
