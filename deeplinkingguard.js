'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'deeplinking', prefix: 'DEEPLINKI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDeeplinkingGuard: guard.evaluate,
  summarizeDeeplinkingGuard: guard.summarize,
  describeDeeplinkingGuard: guard.describe,
};
