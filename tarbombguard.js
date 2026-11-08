'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tarbomb', prefix: 'TARBOMB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTarbombGuard: guard.evaluate,
  summarizeTarbombGuard: guard.summarize,
  describeTarbombGuard: guard.describe,
};
