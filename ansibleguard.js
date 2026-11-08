'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ansible', prefix: 'ANSIBLE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAnsibleGuard: guard.evaluate,
  summarizeAnsibleGuard: guard.summarize,
  describeAnsibleGuard: guard.describe,
};
