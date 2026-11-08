'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'windowopenpolicy', prefix: 'WINDOWOPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWindowopenpolicyGuard: guard.evaluate,
  summarizeWindowopenpolicyGuard: guard.summarize,
  describeWindowopenpolicyGuard: guard.describe,
};
