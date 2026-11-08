'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dbussystemd', prefix: 'DBUSSYSTE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDbussystemdGuard: guard.evaluate,
  summarizeDbussystemdGuard: guard.summarize,
  describeDbussystemdGuard: guard.describe,
};
