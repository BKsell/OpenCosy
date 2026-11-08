'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bearerstore', prefix: 'BEARERSTO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBearerstoreGuard: guard.evaluate,
  summarizeBearerstoreGuard: guard.summarize,
  describeBearerstoreGuard: guard.describe,
};
