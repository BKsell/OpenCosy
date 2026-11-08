'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'screenwake', prefix: 'SCREENWAK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateScreenwakeGuard: guard.evaluate,
  summarizeScreenwakeGuard: guard.summarize,
  describeScreenwakeGuard: guard.describe,
};
