'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'auditd', prefix: 'AUDITD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAuditdGuard: guard.evaluate,
  summarizeAuditdGuard: guard.summarize,
  describeAuditdGuard: guard.describe,
};
