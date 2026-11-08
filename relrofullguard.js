'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'relrofull', prefix: 'RELROFULL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRelrofullGuard: guard.evaluate,
  summarizeRelrofullGuard: guard.summarize,
  describeRelrofullGuard: guard.describe,
};
