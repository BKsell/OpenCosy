'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'splice', prefix: 'SPLICE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpliceGuard: guard.evaluate,
  summarizeSpliceGuard: guard.summarize,
  describeSpliceGuard: guard.describe,
};
