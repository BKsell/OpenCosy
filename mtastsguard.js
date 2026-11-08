'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mtasts', prefix: 'MTASTS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMtastsGuard: guard.evaluate,
  summarizeMtastsGuard: guard.summarize,
  describeMtastsGuard: guard.describe,
};
