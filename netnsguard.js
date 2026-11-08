'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'netns', prefix: 'NETNS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNetnsGuard: guard.evaluate,
  summarizeNetnsGuard: guard.summarize,
  describeNetnsGuard: guard.describe,
};
