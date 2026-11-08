'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'printpermission', prefix: 'PRINTPERM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePrintpermissionGuard: guard.evaluate,
  summarizePrintpermissionGuard: guard.summarize,
  describePrintpermissionGuard: guard.describe,
};
