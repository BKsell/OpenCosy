'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pem', prefix: 'PEM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePemGuard: guard.evaluate,
  summarizePemGuard: guard.summarize,
  describePemGuard: guard.describe,
};
