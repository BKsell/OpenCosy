'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'XXSSPROTE', label: 'X-XSS-Protection legacy header' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXxssprotectionlegacyGuard: guard.evaluate,
  describeXxssprotectionlegacyGuard: guard.describe,
};
