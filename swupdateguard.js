'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'swupdate', prefix: 'SWUPDATE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSwupdateGuard: guard.evaluate,
  summarizeSwupdateGuard: guard.summarize,
  describeSwupdateGuard: guard.describe,
};
