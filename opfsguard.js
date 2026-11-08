'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'opfs', prefix: 'OPFS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOpfsGuard: guard.evaluate,
  summarizeOpfsGuard: guard.summarize,
  describeOpfsGuard: guard.describe,
};
