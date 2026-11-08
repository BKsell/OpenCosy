'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'scim', prefix: 'SCIM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateScimGuard: guard.evaluate,
  summarizeScimGuard: guard.summarize,
  describeScimGuard: guard.describe,
};
