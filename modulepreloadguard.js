'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'modulepreload', prefix: 'MODULEPRE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateModulepreloadGuard: guard.evaluate,
  summarizeModulepreloadGuard: guard.summarize,
  describeModulepreloadGuard: guard.describe,
};
