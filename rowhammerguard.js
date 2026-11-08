'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rowhammer', prefix: 'ROWHAMMER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRowhammerGuard: guard.evaluate,
  summarizeRowhammerGuard: guard.summarize,
  describeRowhammerGuard: guard.describe,
};
