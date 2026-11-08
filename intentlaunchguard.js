'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'intentlaunch', prefix: 'INTENTLAU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIntentlaunchGuard: guard.evaluate,
  summarizeIntentlaunchGuard: guard.summarize,
  describeIntentlaunchGuard: guard.describe,
};
