'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'wasmsimd', prefix: 'WASMSIMD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWasmsimdGuard: guard.evaluate,
  summarizeWasmsimdGuard: guard.summarize,
  describeWasmsimdGuard: guard.describe,
};
