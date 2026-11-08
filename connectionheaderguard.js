'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'connectionheader', prefix: 'CONNECTIO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateConnectionheaderGuard: guard.evaluate,
  summarizeConnectionheaderGuard: guard.summarize,
  describeConnectionheaderGuard: guard.describe,
};
