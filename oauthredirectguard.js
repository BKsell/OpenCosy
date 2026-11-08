'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'oauthredirect', prefix: 'OAUTHREDI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOauthredirectGuard: guard.evaluate,
  summarizeOauthredirectGuard: guard.summarize,
  describeOauthredirectGuard: guard.describe,
};
