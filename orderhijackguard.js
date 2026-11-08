'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'orderhijack', prefix: 'ORDERHIJA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOrderhijackGuard: guard.evaluate,
  summarizeOrderhijackGuard: guard.summarize,
  describeOrderhijackGuard: guard.describe,
};
