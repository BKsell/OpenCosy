'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sev', prefix: 'SEV' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSevGuard: guard.evaluate,
  summarizeSevGuard: guard.summarize,
  describeSevGuard: guard.describe,
};
