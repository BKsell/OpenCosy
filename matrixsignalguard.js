'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'matrixsignal', prefix: 'MATRIXSIG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMatrixsignalGuard: guard.evaluate,
  summarizeMatrixsignalGuard: guard.summarize,
  describeMatrixsignalGuard: guard.describe,
};
