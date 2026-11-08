'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'wasmeval', prefix: 'WASMEVAL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWasmevalGuard: guard.evaluate,
  summarizeWasmevalGuard: guard.summarize,
  describeWasmevalGuard: guard.describe,
};
