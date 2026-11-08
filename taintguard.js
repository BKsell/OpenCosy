'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'taint', prefix: 'TAINT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTaintGuard: guard.evaluate,
  summarizeTaintGuard: guard.summarize,
  describeTaintGuard: guard.describe,
};
