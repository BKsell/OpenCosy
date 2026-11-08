'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'quotaestimate', prefix: 'QUOTAESTI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateQuotaestimateGuard: guard.evaluate,
  summarizeQuotaestimateGuard: guard.summarize,
  describeQuotaestimateGuard: guard.describe,
};
