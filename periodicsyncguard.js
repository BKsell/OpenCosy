'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'periodicsync', prefix: 'PERIODICS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePeriodicsyncGuard: guard.evaluate,
  summarizePeriodicsyncGuard: guard.summarize,
  describePeriodicsyncGuard: guard.describe,
};
