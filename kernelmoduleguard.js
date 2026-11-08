'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'kernelmodule', prefix: 'KERNELMOD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKernelmoduleGuard: guard.evaluate,
  summarizeKernelmoduleGuard: guard.summarize,
  describeKernelmoduleGuard: guard.describe,
};
