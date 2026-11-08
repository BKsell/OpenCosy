'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'iampolicy', prefix: 'IAMPOLICY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIampolicyGuard: guard.evaluate,
  summarizeIampolicyGuard: guard.summarize,
  describeIampolicyGuard: guard.describe,
};
