'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'intoto', prefix: 'INTOTO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIntotoGuard: guard.evaluate,
  summarizeIntotoGuard: guard.summarize,
  describeIntotoGuard: guard.describe,
};
