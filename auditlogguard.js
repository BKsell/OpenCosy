'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'auditlog', prefix: 'AUDITLOG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAuditlogGuard: guard.evaluate,
  summarizeAuditlogGuard: guard.summarize,
  describeAuditlogGuard: guard.describe,
};
