'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'quota', prefix: 'QUOTA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateQuotaGuard: guard.evaluate,
  summarizeQuotaGuard: guard.summarize,
  describeQuotaGuard: guard.describe,
};
