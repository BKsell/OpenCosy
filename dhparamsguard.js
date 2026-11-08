'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dhparams', prefix: 'DHPARAMS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDhparamsGuard: guard.evaluate,
  summarizeDhparamsGuard: guard.summarize,
  describeDhparamsGuard: guard.describe,
};
