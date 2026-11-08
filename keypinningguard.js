'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'keypinning', prefix: 'KEYPINNIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKeypinningGuard: guard.evaluate,
  summarizeKeypinningGuard: guard.summarize,
  describeKeypinningGuard: guard.describe,
};
