'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'weakcrypto', prefix: 'WEAKCRYPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWeakcryptoGuard: guard.evaluate,
  summarizeWeakcryptoGuard: guard.summarize,
  describeWeakcryptoGuard: guard.describe,
};
