'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'setuid', prefix: 'SETUID' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSetuidGuard: guard.evaluate,
  summarizeSetuidGuard: guard.summarize,
  describeSetuidGuard: guard.describe,
};
