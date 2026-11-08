'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'websqldb', prefix: 'WEBSQLDB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebsqldbGuard: guard.evaluate,
  summarizeWebsqldbGuard: guard.summarize,
  describeWebsqldbGuard: guard.describe,
};
