'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smime', prefix: 'SMIME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmimeGuard: guard.evaluate,
  summarizeSmimeGuard: guard.summarize,
  describeSmimeGuard: guard.describe,
};
