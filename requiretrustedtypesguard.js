'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'requiretrustedtypes', prefix: 'REQUIRETR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRequiretrustedtypesGuard: guard.evaluate,
  summarizeRequiretrustedtypesGuard: guard.summarize,
  describeRequiretrustedtypesGuard: guard.describe,
};
