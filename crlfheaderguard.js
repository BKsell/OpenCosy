'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'crlfheader', prefix: 'CRLFHEADE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCrlfheaderGuard: guard.evaluate,
  summarizeCrlfheaderGuard: guard.summarize,
  describeCrlfheaderGuard: guard.describe,
};
