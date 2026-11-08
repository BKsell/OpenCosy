'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'oauthpc', prefix: 'OAUTHPC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOauthpcGuard: guard.evaluate,
  summarizeOauthpcGuard: guard.summarize,
  describeOauthpcGuard: guard.describe,
};
