'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'leapyear', prefix: 'LEAPYEAR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLeapyearGuard: guard.evaluate,
  summarizeLeapyearGuard: guard.summarize,
  describeLeapyearGuard: guard.describe,
};
