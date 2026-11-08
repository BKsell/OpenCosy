'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'saml', prefix: 'SAML' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSamlGuard: guard.evaluate,
  summarizeSamlGuard: guard.summarize,
  describeSamlGuard: guard.describe,
};
