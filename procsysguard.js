'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'procsys', prefix: 'PROCSYS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProcsysGuard: guard.evaluate,
  summarizeProcsysGuard: guard.summarize,
  describeProcsysGuard: guard.describe,
};
