'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cronnext', prefix: 'CRONNEXT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCronnextGuard: guard.evaluate,
  summarizeCronnextGuard: guard.summarize,
  describeCronnextGuard: guard.describe,
};
