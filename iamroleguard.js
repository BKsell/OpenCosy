'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'iamrole', prefix: 'IAMROLE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIamroleGuard: guard.evaluate,
  summarizeIamroleGuard: guard.summarize,
  describeIamroleGuard: guard.describe,
};
