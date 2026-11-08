'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ntlm', prefix: 'NTLM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNtlmGuard: guard.evaluate,
  summarizeNtlmGuard: guard.summarize,
  describeNtlmGuard: guard.describe,
};
