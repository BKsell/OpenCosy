'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pkcs', prefix: 'PKCS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePkcsGuard: guard.evaluate,
  summarizePkcsGuard: guard.summarize,
  describePkcsGuard: guard.describe,
};
