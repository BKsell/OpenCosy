'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'paymentrequest', prefix: 'PAYMENTRE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePaymentrequestGuard: guard.evaluate,
  summarizePaymentrequestGuard: guard.summarize,
  describePaymentrequestGuard: guard.describe,
};
