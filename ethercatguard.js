'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ethercat', prefix: 'ETHERCAT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEthercatGuard: guard.evaluate,
  summarizeEthercatGuard: guard.summarize,
  describeEthercatGuard: guard.describe,
};
