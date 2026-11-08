'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pathcookie', prefix: 'PATHCOOKI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePathcookieGuard: guard.evaluate,
  summarizePathcookieGuard: guard.summarize,
  describePathcookieGuard: guard.describe,
};
