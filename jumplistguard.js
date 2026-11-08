'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jumplist', prefix: 'JUMPLIST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJumplistGuard: guard.evaluate,
  summarizeJumplistGuard: guard.summarize,
  describeJumplistGuard: guard.describe,
};
