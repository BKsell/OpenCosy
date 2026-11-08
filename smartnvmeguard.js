'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smartnvme', prefix: 'SMARTNVME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmartnvmeGuard: guard.evaluate,
  summarizeSmartnvmeGuard: guard.summarize,
  describeSmartnvmeGuard: guard.describe,
};
