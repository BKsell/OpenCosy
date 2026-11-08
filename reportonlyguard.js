'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'reportonly', prefix: 'REPORTONL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReportonlyGuard: guard.evaluate,
  summarizeReportonlyGuard: guard.summarize,
  describeReportonlyGuard: guard.describe,
};
