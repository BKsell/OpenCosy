'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'aia', prefix: 'AIA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAiaGuard: guard.evaluate,
  summarizeAiaGuard: guard.summarize,
  describeAiaGuard: guard.describe,
};
