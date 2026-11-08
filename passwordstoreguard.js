'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'passwordstore', prefix: 'PASSWORDS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePasswordstoreGuard: guard.evaluate,
  summarizePasswordstoreGuard: guard.summarize,
  describePasswordstoreGuard: guard.describe,
};
