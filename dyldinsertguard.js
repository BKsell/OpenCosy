'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dyldinsert', prefix: 'DYLDINSER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDyldinsertGuard: guard.evaluate,
  summarizeDyldinsertGuard: guard.summarize,
  describeDyldinsertGuard: guard.describe,
};
