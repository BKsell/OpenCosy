'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pcr', prefix: 'PCR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePcrGuard: guard.evaluate,
  summarizePcrGuard: guard.summarize,
  describePcrGuard: guard.describe,
};
