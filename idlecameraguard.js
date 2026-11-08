'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'idlecamera', prefix: 'IDLECAMER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIdlecameraGuard: guard.evaluate,
  summarizeIdlecameraGuard: guard.summarize,
  describeIdlecameraGuard: guard.describe,
};
