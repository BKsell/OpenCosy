'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dbx', prefix: 'DBX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDbxGuard: guard.evaluate,
  summarizeDbxGuard: guard.summarize,
  describeDbxGuard: guard.describe,
};
