'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nsswitch', prefix: 'NSSWITCH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNsswitchGuard: guard.evaluate,
  summarizeNsswitchGuard: guard.summarize,
  describeNsswitchGuard: guard.describe,
};
