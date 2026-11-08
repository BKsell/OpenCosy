'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tar', prefix: 'TAR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTarGuard: guard.evaluate,
  summarizeTarGuard: guard.summarize,
  describeTarGuard: guard.describe,
};
