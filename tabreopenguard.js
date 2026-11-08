'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabreopen', prefix: 'TABREOPEN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabreopenGuard: guard.evaluate,
  summarizeTabreopenGuard: guard.summarize,
  describeTabreopenGuard: guard.describe,
};
