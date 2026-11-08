'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cmac', prefix: 'CMAC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCmacGuard: guard.evaluate,
  summarizeCmacGuard: guard.summarize,
  describeCmacGuard: guard.describe,
};
