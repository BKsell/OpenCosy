'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'shake', prefix: 'SHAKE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateShakeGuard: guard.evaluate,
  summarizeShakeGuard: guard.summarize,
  describeShakeGuard: guard.describe,
};
