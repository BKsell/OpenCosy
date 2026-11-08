'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'corsmethod', prefix: 'CORSMETHO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorsmethodGuard: guard.evaluate,
  summarizeCorsmethodGuard: guard.summarize,
  describeCorsmethodGuard: guard.describe,
};
