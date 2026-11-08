'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'userns', prefix: 'USERNS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUsernsGuard: guard.evaluate,
  summarizeUsernsGuard: guard.summarize,
  describeUsernsGuard: guard.describe,
};
