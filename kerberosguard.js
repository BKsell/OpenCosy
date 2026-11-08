'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'kerberos', prefix: 'KERBEROS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKerberosGuard: guard.evaluate,
  summarizeKerberosGuard: guard.summarize,
  describeKerberosGuard: guard.describe,
};
