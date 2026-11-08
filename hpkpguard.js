'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hpkp', prefix: 'HPKP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHpkpGuard: guard.evaluate,
  summarizeHpkpGuard: guard.summarize,
  describeHpkpGuard: guard.describe,
};
