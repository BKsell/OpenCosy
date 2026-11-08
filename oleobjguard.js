'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'oleobj', prefix: 'OLEOBJ' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOleobjGuard: guard.evaluate,
  summarizeOleobjGuard: guard.summarize,
  describeOleobjGuard: guard.describe,
};
