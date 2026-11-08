'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'keyctl', prefix: 'KEYCTL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKeyctlGuard: guard.evaluate,
  summarizeKeyctlGuard: guard.summarize,
  describeKeyctlGuard: guard.describe,
};
