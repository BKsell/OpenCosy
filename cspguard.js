'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'csp', prefix: 'CSP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspGuard: guard.evaluate,
  summarizeCspGuard: guard.summarize,
  describeCspGuard: guard.describe,
};
