'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'preflight', prefix: 'PREFLIGHT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePreflightGuard: guard.evaluate,
  summarizePreflightGuard: guard.summarize,
  describePreflightGuard: guard.describe,
};
