'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'secureboot', prefix: 'SECUREBOO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSecurebootGuard: guard.evaluate,
  summarizeSecurebootGuard: guard.summarize,
  describeSecurebootGuard: guard.describe,
};
