'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'globalprivacycontrol', prefix: 'GLOBALPRI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGlobalprivacycontrolGuard: guard.evaluate,
  summarizeGlobalprivacycontrolGuard: guard.summarize,
  describeGlobalprivacycontrolGuard: guard.describe,
};
