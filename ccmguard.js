'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ccm', prefix: 'CCM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCcmGuard: guard.evaluate,
  summarizeCcmGuard: guard.summarize,
  describeCcmGuard: guard.describe,
};
