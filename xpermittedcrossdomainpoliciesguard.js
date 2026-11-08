'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'XPERMITTE', label: 'X-Permitted-Cross-Domain-Policies' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXpermittedcrossdomainpoliciesGuard: guard.evaluate,
  describeXpermittedcrossdomainpoliciesGuard: guard.describe,
};
