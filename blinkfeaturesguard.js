'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'blinkfeatures', prefix: 'BLINKFEAT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBlinkfeaturesGuard: guard.evaluate,
  summarizeBlinkfeaturesGuard: guard.summarize,
  describeBlinkfeaturesGuard: guard.describe,
};
