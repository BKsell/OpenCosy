'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'edrhook', prefix: 'EDRHOOK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEdrhookGuard: guard.evaluate,
  summarizeEdrhookGuard: guard.summarize,
  describeEdrhookGuard: guard.describe,
};
