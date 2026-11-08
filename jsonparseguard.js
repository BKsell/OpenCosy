'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jsonparse', prefix: 'JSONPARSE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJsonparseGuard: guard.evaluate,
  summarizeJsonparseGuard: guard.summarize,
  describeJsonparseGuard: guard.describe,
};
