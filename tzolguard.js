'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tzol', prefix: 'TZOL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTzolGuard: guard.evaluate,
  summarizeTzolGuard: guard.summarize,
  describeTzolGuard: guard.describe,
};
