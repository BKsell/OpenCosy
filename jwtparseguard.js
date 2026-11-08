'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jwtparse', prefix: 'JWTPARSE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJwtparseGuard: guard.evaluate,
  summarizeJwtparseGuard: guard.summarize,
  describeJwtparseGuard: guard.describe,
};
