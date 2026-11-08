'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hmac', prefix: 'HMAC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHmacGuard: guard.evaluate,
  summarizeHmacGuard: guard.summarize,
  describeHmacGuard: guard.describe,
};
