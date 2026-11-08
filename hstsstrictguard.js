'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hstsstrict', prefix: 'HSTSSTRIC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHstsstrictGuard: guard.evaluate,
  summarizeHstsstrictGuard: guard.summarize,
  describeHstsstrictGuard: guard.describe,
};
