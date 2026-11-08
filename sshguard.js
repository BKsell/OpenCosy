'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ssh', prefix: 'SSH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSshGuard: guard.evaluate,
  summarizeSshGuard: guard.summarize,
  describeSshGuard: guard.describe,
};
