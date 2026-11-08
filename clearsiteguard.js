'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'clearsite', prefix: 'CLEARSITE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateClearsiteGuard: guard.evaluate,
  summarizeClearsiteGuard: guard.summarize,
  describeClearsiteGuard: guard.describe,
};
