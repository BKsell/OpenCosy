'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ima', prefix: 'IMA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateImaGuard: guard.evaluate,
  summarizeImaGuard: guard.summarize,
  describeImaGuard: guard.describe,
};
