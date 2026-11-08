'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'websql', prefix: 'WEBSQL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebsqlGuard: guard.evaluate,
  summarizeWebsqlGuard: guard.summarize,
  describeWebsqlGuard: guard.describe,
};
