'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'COEPREQUI', label: 'Cross-Origin-Embedder-Policy require-corp' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCoeprequirecorpGuard: guard.evaluate,
  describeCoeprequirecorpGuard: guard.describe,
};
