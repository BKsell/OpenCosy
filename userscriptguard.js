'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'userscript', prefix: 'USERSCRIP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUserscriptGuard: guard.evaluate,
  summarizeUserscriptGuard: guard.summarize,
  describeUserscriptGuard: guard.describe,
};
