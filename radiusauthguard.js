'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'radiusauth', prefix: 'RADIUSAUT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRadiusauthGuard: guard.evaluate,
  summarizeRadiusauthGuard: guard.summarize,
  describeRadiusauthGuard: guard.describe,
};
