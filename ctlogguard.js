'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ctlog', prefix: 'CTLOG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCtlogGuard: guard.evaluate,
  summarizeCtlogGuard: guard.summarize,
  describeCtlogGuard: guard.describe,
};
