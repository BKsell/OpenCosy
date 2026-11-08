'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sessionkeyring', prefix: 'SESSIONKE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSessionkeyringGuard: guard.evaluate,
  summarizeSessionkeyringGuard: guard.summarize,
  describeSessionkeyringGuard: guard.describe,
};
