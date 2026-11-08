'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gps', prefix: 'GPS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGpsGuard: guard.evaluate,
  summarizeGpsGuard: guard.summarize,
  describeGpsGuard: guard.describe,
};
