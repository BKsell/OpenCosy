'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'scriptinject', prefix: 'SCRIPTINJ' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateScriptinjectGuard: guard.evaluate,
  summarizeScriptinjectGuard: guard.summarize,
  describeScriptinjectGuard: guard.describe,
};
