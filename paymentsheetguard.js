'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'paymentsheet', prefix: 'PAYMENTSH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePaymentsheetGuard: guard.evaluate,
  summarizePaymentsheetGuard: guard.summarize,
  describePaymentsheetGuard: guard.describe,
};
