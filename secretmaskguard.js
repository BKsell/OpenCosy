'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'secretmask', prefix: 'SECRETMAS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSecretmaskGuard: guard.evaluate,
  summarizeSecretmaskGuard: guard.summarize,
  describeSecretmaskGuard: guard.describe,
};
