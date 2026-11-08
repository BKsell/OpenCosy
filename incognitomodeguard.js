'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'incognitomode', prefix: 'INCOGNITO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIncognitomodeGuard: guard.evaluate,
  summarizeIncognitomodeGuard: guard.summarize,
  describeIncognitomodeGuard: guard.describe,
};
