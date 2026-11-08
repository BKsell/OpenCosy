'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'datauri', prefix: 'DATAURI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDatauriGuard: guard.evaluate,
  summarizeDatauriGuard: guard.summarize,
  describeDatauriGuard: guard.describe,
};
