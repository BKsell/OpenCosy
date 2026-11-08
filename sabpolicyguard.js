'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sabpolicy', prefix: 'SABPOLICY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSabpolicyGuard: guard.evaluate,
  summarizeSabpolicyGuard: guard.summarize,
  describeSabpolicyGuard: guard.describe,
};
