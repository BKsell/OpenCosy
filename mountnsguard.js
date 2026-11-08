'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mountns', prefix: 'MOUNTNS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMountnsGuard: guard.evaluate,
  summarizeMountnsGuard: guard.summarize,
  describeMountnsGuard: guard.describe,
};
