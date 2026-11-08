'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'printjob', prefix: 'PRINTJOB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePrintjobGuard: guard.evaluate,
  summarizePrintjobGuard: guard.summarize,
  describePrintjobGuard: guard.describe,
};
