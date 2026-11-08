'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jdwp', prefix: 'JDWP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJdwpGuard: guard.evaluate,
  summarizeJdwpGuard: guard.summarize,
  describeJdwpGuard: guard.describe,
};
