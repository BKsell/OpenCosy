'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ocsp', prefix: 'OCSP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOcspGuard: guard.evaluate,
  summarizeOcspGuard: guard.summarize,
  describeOcspGuard: guard.describe,
};
