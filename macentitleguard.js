'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'macentitle', prefix: 'MACENTITL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMacentitleGuard: guard.evaluate,
  summarizeMacentitleGuard: guard.summarize,
  describeMacentitleGuard: guard.describe,
};
