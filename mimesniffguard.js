'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mimesniff', prefix: 'MIMESNIFF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMimesniffGuard: guard.evaluate,
  summarizeMimesniffGuard: guard.summarize,
  describeMimesniffGuard: guard.describe,
};
