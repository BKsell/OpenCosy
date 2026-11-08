'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tsa', prefix: 'TSA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTsaGuard: guard.evaluate,
  summarizeTsaGuard: guard.summarize,
  describeTsaGuard: guard.describe,
};
