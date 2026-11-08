'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'journald', prefix: 'JOURNALD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJournaldGuard: guard.evaluate,
  summarizeJournaldGuard: guard.summarize,
  describeJournaldGuard: guard.describe,
};
