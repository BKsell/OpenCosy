'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'threaddump', prefix: 'THREADDUM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateThreaddumpGuard: guard.evaluate,
  summarizeThreaddumpGuard: guard.summarize,
  describeThreaddumpGuard: guard.describe,
};
