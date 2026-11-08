'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cspupgradeinsecure', prefix: 'CSPUPGRAD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspupgradeinsecureGuard: guard.evaluate,
  summarizeCspupgradeinsecureGuard: guard.summarize,
  describeCspupgradeinsecureGuard: guard.describe,
};
