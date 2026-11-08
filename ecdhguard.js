'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ecdh', prefix: 'ECDH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEcdhGuard: guard.evaluate,
  summarizeEcdhGuard: guard.summarize,
  describeEcdhGuard: guard.describe,
};
