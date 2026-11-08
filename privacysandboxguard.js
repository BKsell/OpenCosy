'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'privacysandbox', prefix: 'PRIVACYSA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePrivacysandboxGuard: guard.evaluate,
  summarizePrivacysandboxGuard: guard.summarize,
  describePrivacysandboxGuard: guard.describe,
};
