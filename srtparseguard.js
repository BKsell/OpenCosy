'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'srtparse', prefix: 'SRTPARSE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSrtparseGuard: guard.evaluate,
  summarizeSrtparseGuard: guard.summarize,
  describeSrtparseGuard: guard.describe,
};
