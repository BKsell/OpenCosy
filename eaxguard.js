'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'eax', prefix: 'EAX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEaxGuard: guard.evaluate,
  summarizeEaxGuard: guard.summarize,
  describeEaxGuard: guard.describe,
};
