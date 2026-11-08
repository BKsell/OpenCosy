'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'grubpassword', prefix: 'GRUBPASSW' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGrubpasswordGuard: guard.evaluate,
  summarizeGrubpasswordGuard: guard.summarize,
  describeGrubpasswordGuard: guard.describe,
};
