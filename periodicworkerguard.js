'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'periodicworker', prefix: 'PERIODICW' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePeriodicworkerGuard: guard.evaluate,
  summarizePeriodicworkerGuard: guard.summarize,
  describePeriodicworkerGuard: guard.describe,
};
