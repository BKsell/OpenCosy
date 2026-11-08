'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dkim', prefix: 'DKIM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDkimGuard: guard.evaluate,
  summarizeDkimGuard: guard.summarize,
  describeDkimGuard: guard.describe,
};
