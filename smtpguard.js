'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smtp', prefix: 'SMTP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmtpGuard: guard.evaluate,
  summarizeSmtpGuard: guard.summarize,
  describeSmtpGuard: guard.describe,
};
