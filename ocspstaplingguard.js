'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ocspstapling', prefix: 'OCSPSTAPL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOcspstaplingGuard: guard.evaluate,
  summarizeOcspstaplingGuard: guard.summarize,
  describeOcspstaplingGuard: guard.describe,
};
