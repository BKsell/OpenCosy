'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gmac', prefix: 'GMAC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGmacGuard: guard.evaluate,
  summarizeGmacGuard: guard.summarize,
  describeGmacGuard: guard.describe,
};
