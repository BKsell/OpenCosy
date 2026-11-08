'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'denylist', prefix: 'DENYLIST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDenylistGuard: guard.evaluate,
  summarizeDenylistGuard: guard.summarize,
  describeDenylistGuard: guard.describe,
};
