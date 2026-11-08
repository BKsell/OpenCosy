'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'polkit', prefix: 'POLKIT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePolkitGuard: guard.evaluate,
  summarizePolkitGuard: guard.summarize,
  describePolkitGuard: guard.describe,
};
