'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'downloaditem', prefix: 'DOWNLOADI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDownloaditemGuard: guard.evaluate,
  summarizeDownloaditemGuard: guard.summarize,
  describeDownloaditemGuard: guard.describe,
};
