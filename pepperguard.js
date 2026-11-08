'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pepper', prefix: 'PEPPER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePepperGuard: guard.evaluate,
  summarizePepperGuard: guard.summarize,
  describePepperGuard: guard.describe,
};
