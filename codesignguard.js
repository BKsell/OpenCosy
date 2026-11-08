'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'codesign', prefix: 'CODESIGN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCodesignGuard: guard.evaluate,
  summarizeCodesignGuard: guard.summarize,
  describeCodesignGuard: guard.describe,
};
