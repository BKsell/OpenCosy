function describeReasonFrom(table, reason, fallback) {
  return Object.prototype.hasOwnProperty.call(table, reason) ? table[reason] : fallback;
}

function describeReasonTable(table, fallback) {
  return function describeReason(reason) {
    return describeReasonFrom(table, reason, fallback);
  };
}

module.exports = { describeReasonFrom, describeReasonTable };
