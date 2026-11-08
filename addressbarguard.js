'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'addressbar', prefix: 'ADDRESSBA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAddressbarGuard: guard.evaluate,
  summarizeAddressbarGuard: guard.summarize,
  describeAddressbarGuard: guard.describe,
};
