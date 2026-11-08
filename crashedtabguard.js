'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'crashedtab', prefix: 'CRASHEDTA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCrashedtabGuard: guard.evaluate,
  summarizeCrashedtabGuard: guard.summarize,
  describeCrashedtabGuard: guard.describe,
};
