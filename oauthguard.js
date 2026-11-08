'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'oauth', prefix: 'OAUTH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOauthGuard: guard.evaluate,
  summarizeOauthGuard: guard.summarize,
  describeOauthGuard: guard.describe,
};
