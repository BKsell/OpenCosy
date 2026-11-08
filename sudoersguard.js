'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sudoers', prefix: 'SUDOERS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSudoersGuard: guard.evaluate,
  summarizeSudoersGuard: guard.summarize,
  describeSudoersGuard: guard.describe,
};
