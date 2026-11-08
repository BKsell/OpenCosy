'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smtpstarttls', prefix: 'SMTPSTART' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmtpstarttlsGuard: guard.evaluate,
  summarizeSmtpstarttlsGuard: guard.summarize,
  describeSmtpstarttlsGuard: guard.describe,
};
