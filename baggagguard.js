'use strict';

const { REASON, applyStructuredHeaderGuard } = require('./structuredheaderguard_core');

const HEADER = 'baggage';
const MAX_MEMBERS = 16;
const MAX_LENGTH = 4096;
const MEMBER = /^[A-Za-z0-9_.-]{1,64}=[\x20-\x7e]{0,256}(;[A-Za-z0-9_.-]{1,64}=[\x20-\x7e]{0,128}){0,3}$/;

function applyBaggageGuard(headers) {
  return applyStructuredHeaderGuard(headers, {
    header: HEADER,
    maxEntries: MAX_MEMBERS,
    maxLength: MAX_LENGTH,
    member: MEMBER,
  });
}

module.exports = { REASON, applyBaggageGuard };
