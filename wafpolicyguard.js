'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'wafpolicy', prefix: 'WAFPOLICY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWafpolicyGuard: guard.evaluate,
  summarizeWafpolicyGuard: guard.summarize,
  describeWafpolicyGuard: guard.describe,
};
