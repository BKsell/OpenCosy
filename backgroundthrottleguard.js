'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'backgroundthrottle', prefix: 'BACKGROUN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBackgroundthrottleGuard: guard.evaluate,
  summarizeBackgroundthrottleGuard: guard.summarize,
  describeBackgroundthrottleGuard: guard.describe,
};
