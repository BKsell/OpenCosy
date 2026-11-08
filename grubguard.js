'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'grub', prefix: 'GRUB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGrubGuard: guard.evaluate,
  summarizeGrubGuard: guard.summarize,
  describeGrubGuard: guard.describe,
};
