'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'doubleratchet', prefix: 'DOUBLERAT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDoubleratchetGuard: guard.evaluate,
  summarizeDoubleratchetGuard: guard.summarize,
  describeDoubleratchetGuard: guard.describe,
};
