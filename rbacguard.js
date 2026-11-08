'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rbac', prefix: 'RBAC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRbacGuard: guard.evaluate,
  summarizeRbacGuard: guard.summarize,
  describeRbacGuard: guard.describe,
};
