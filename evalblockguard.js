'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'evalblock', prefix: 'EVALBLOCK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEvalblockGuard: guard.evaluate,
  summarizeEvalblockGuard: guard.summarize,
  describeEvalblockGuard: guard.describe,
};
