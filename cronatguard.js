'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cronat', prefix: 'CRONAT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCronatGuard: guard.evaluate,
  summarizeCronatGuard: guard.summarize,
  describeCronatGuard: guard.describe,
};
