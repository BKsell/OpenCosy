'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'normalize', prefix: 'NORMALIZE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNormalizeGuard: guard.evaluate,
  summarizeNormalizeGuard: guard.summarize,
  describeNormalizeGuard: guard.describe,
};
