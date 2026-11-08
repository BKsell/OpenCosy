'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'HSTSINCLU', label: 'HSTS includeSubDomains' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHstsincludesubdomainsGuard: guard.evaluate,
  describeHstsincludesubdomainsGuard: guard.describe,
};
