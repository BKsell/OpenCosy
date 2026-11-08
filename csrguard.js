'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'csr', prefix: 'CSR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCsrGuard: guard.evaluate,
  summarizeCsrGuard: guard.summarize,
  describeCsrGuard: guard.describe,
};
