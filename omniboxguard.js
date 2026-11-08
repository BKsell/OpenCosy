'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'omnibox', prefix: 'OMNIBOX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOmniboxGuard: guard.evaluate,
  summarizeOmniboxGuard: guard.summarize,
  describeOmniboxGuard: guard.describe,
};
