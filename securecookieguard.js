'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'securecookie', prefix: 'SECURECOO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSecurecookieGuard: guard.evaluate,
  summarizeSecurecookieGuard: guard.summarize,
  describeSecurecookieGuard: guard.describe,
};
