'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'passkeywebauth', prefix: 'PASSKEYWE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePasskeywebauthGuard: guard.evaluate,
  summarizePasskeywebauthGuard: guard.summarize,
  describePasskeywebauthGuard: guard.describe,
};
