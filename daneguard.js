'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dane', prefix: 'DANE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDaneGuard: guard.evaluate,
  summarizeDaneGuard: guard.summarize,
  describeDaneGuard: guard.describe,
};
