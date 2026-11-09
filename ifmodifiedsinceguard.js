'use strict';
const { REASON, checkConditionalDate } = require('./conditionaldate');

const HEADER = 'if-modified-since';

function applyIfModifiedSinceGuard(headers) {
  return checkConditionalDate(headers, HEADER);
}

module.exports = { REASON, applyIfModifiedSinceGuard };
