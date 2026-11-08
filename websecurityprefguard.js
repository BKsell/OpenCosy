'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'websecuritypref', prefix: 'WEBSECURI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebsecurityprefGuard: guard.evaluate,
  summarizeWebsecurityprefGuard: guard.summarize,
  describeWebsecurityprefGuard: guard.describe,
};
