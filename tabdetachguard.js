'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabdetach', prefix: 'TABDETACH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabdetachGuard: guard.evaluate,
  summarizeTabdetachGuard: guard.summarize,
  describeTabdetachGuard: guard.describe,
};
