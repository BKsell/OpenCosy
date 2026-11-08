'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smapbit', prefix: 'SMAPBIT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmapbitGuard: guard.evaluate,
  summarizeSmapbitGuard: guard.summarize,
  describeSmapbitGuard: guard.describe,
};
