'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'webworker', prefix: 'WEBWORKER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebworkerGuard: guard.evaluate,
  summarizeWebworkerGuard: guard.summarize,
  describeWebworkerGuard: guard.describe,
};
