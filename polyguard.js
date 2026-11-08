'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'poly', prefix: 'POLY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePolyGuard: guard.evaluate,
  summarizePolyGuard: guard.summarize,
  describePolyGuard: guard.describe,
};
