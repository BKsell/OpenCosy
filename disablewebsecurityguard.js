'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'disablewebsecurity', prefix: 'DISABLEWE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDisablewebsecurityGuard: guard.evaluate,
  summarizeDisablewebsecurityGuard: guard.summarize,
  describeDisablewebsecurityGuard: guard.describe,
};
