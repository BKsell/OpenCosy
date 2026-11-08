'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'updatersignature', prefix: 'UPDATERSI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUpdatersignatureGuard: guard.evaluate,
  summarizeUpdatersignatureGuard: guard.summarize,
  describeUpdatersignatureGuard: guard.describe,
};
