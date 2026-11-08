'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'azuremeta', prefix: 'AZUREMETA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAzuremetaGuard: guard.evaluate,
  summarizeAzuremetaGuard: guard.summarize,
  describeAzuremetaGuard: guard.describe,
};
