'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'passkey', prefix: 'PASSKEY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePasskeyGuard: guard.evaluate,
  summarizePasskeyGuard: guard.summarize,
  describePasskeyGuard: guard.describe,
};
