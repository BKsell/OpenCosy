'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ofb', prefix: 'OFB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOfbGuard: guard.evaluate,
  summarizeOfbGuard: guard.summarize,
  describeOfbGuard: guard.describe,
};
