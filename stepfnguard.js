'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'stepfn', prefix: 'STEPFN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStepfnGuard: guard.evaluate,
  summarizeStepfnGuard: guard.summarize,
  describeStepfnGuard: guard.describe,
};
