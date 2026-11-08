'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'presign', prefix: 'PRESIGN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePresignGuard: guard.evaluate,
  summarizePresignGuard: guard.summarize,
  describePresignGuard: guard.describe,
};
