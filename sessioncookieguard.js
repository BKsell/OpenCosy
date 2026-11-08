'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sessioncookie', prefix: 'SESSIONCO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSessioncookieGuard: guard.evaluate,
  summarizeSessioncookieGuard: guard.summarize,
  describeSessioncookieGuard: guard.describe,
};
