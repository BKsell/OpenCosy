'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'omniboxsuggest', prefix: 'OMNIBOXSU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOmniboxsuggestGuard: guard.evaluate,
  summarizeOmniboxsuggestGuard: guard.summarize,
  describeOmniboxsuggestGuard: guard.describe,
};
