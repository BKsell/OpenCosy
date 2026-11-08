'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dstswap', prefix: 'DSTSWAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDstswapGuard: guard.evaluate,
  summarizeDstswapGuard: guard.summarize,
  describeDstswapGuard: guard.describe,
};
