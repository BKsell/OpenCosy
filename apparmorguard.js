'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'apparmor', prefix: 'APPARMOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateApparmorGuard: guard.evaluate,
  summarizeApparmorGuard: guard.summarize,
  describeApparmorGuard: guard.describe,
};
