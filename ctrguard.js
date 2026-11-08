'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ctr', prefix: 'CTR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCtrGuard: guard.evaluate,
  summarizeCtrGuard: guard.summarize,
  describeCtrGuard: guard.describe,
};
