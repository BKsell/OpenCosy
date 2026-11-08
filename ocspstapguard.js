'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ocspstap', prefix: 'OCSPSTAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOcspstapGuard: guard.evaluate,
  summarizeOcspstapGuard: guard.summarize,
  describeOcspstapGuard: guard.describe,
};
