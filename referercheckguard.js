'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'referercheck', prefix: 'REFERERCH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReferercheckGuard: guard.evaluate,
  summarizeReferercheckGuard: guard.summarize,
  describeReferercheckGuard: guard.describe,
};
