'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'webauthn', prefix: 'WEBAUTHN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebauthnGuard: guard.evaluate,
  summarizeWebauthnGuard: guard.summarize,
  describeWebauthnGuard: guard.describe,
};
