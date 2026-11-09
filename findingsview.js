'use strict';

function describeReasons(findings, emptyMsg, format, limit = 8) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return emptyMsg;
  return list.slice(0, limit).map(format).join('; ');
}

module.exports = { describeReasons };
