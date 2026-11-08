'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'setuidbit', prefix: 'SETUIDBIT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSetuidbitGuard: guard.evaluate,
  summarizeSetuidbitGuard: guard.summarize,
  describeSetuidbitGuard: guard.describe,
};
