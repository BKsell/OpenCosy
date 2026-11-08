'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smep', prefix: 'SMEP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmepGuard: guard.evaluate,
  summarizeSmepGuard: guard.summarize,
  describeSmepGuard: guard.describe,
};
