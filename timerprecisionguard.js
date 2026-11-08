'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'timerprecision', prefix: 'TIMERPREC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTimerprecisionGuard: guard.evaluate,
  summarizeTimerprecisionGuard: guard.summarize,
  describeTimerprecisionGuard: guard.describe,
};
