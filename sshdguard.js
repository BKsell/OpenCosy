'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sshd', prefix: 'SSHD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSshdGuard: guard.evaluate,
  summarizeSshdGuard: guard.summarize,
  describeSshdGuard: guard.describe,
};
