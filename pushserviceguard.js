'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pushservice', prefix: 'PUSHSERVI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePushserviceGuard: guard.evaluate,
  summarizePushserviceGuard: guard.summarize,
  describePushserviceGuard: guard.describe,
};
