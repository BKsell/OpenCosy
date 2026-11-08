'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'contentinject', prefix: 'CONTENTIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateContentinjectGuard: guard.evaluate,
  summarizeContentinjectGuard: guard.summarize,
  describeContentinjectGuard: guard.describe,
};
