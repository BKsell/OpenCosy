'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sketch', prefix: 'SKETCH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSketchGuard: guard.evaluate,
  summarizeSketchGuard: guard.summarize,
  describeSketchGuard: guard.describe,
};
