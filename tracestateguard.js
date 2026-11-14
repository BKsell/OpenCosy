'use strict';

const { REASON, applyStructuredHeaderGuard } = require('./structuredheaderguard_core');

const HEADER = 'tracestate';
const MAX_ENTRIES = 32;
const MAX_LENGTH = 512;
const MEMBER = /^[a-z][a-z0-9_\-*/]{0,255}=[\x20-\x7e]{1,256}$/;

function applyTraceStateGuard(headers) {
  return applyStructuredHeaderGuard(headers, {
    header: HEADER,
    maxEntries: MAX_ENTRIES,
    maxLength: MAX_LENGTH,
    member: MEMBER,
  });
}

module.exports = { REASON, applyTraceStateGuard };
