'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cbc', prefix: 'CBC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCbcGuard: guard.evaluate,
  summarizeCbcGuard: guard.summarize,
  describeCbcGuard: guard.describe,
};
