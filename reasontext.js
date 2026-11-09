function describeReasonFrom(table, reason, fallback) {
  return Object.prototype.hasOwnProperty.call(table, reason) ? table[reason] : fallback;
}

module.exports = { describeReasonFrom };
