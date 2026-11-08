'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabbadge', prefix: 'TABBADGE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabbadgeGuard: guard.evaluate,
  summarizeTabbadgeGuard: guard.summarize,
  describeTabbadgeGuard: guard.describe,
};
