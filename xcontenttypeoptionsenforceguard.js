'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'XCONTENTT', label: 'X-Content-Type-Options' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXcontenttypeoptionsenforceGuard: guard.evaluate,
  describeXcontenttypeoptionsenforceGuard: guard.describe,
};
