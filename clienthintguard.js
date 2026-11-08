'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'clienthint', prefix: 'CLIENTHIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateClienthintGuard: guard.evaluate,
  summarizeClienthintGuard: guard.summarize,
  describeClienthintGuard: guard.describe,
};
