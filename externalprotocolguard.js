'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'externalprotocol', prefix: 'EXTERNALP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateExternalprotocolGuard: guard.evaluate,
  summarizeExternalprotocolGuard: guard.summarize,
  describeExternalprotocolGuard: guard.describe,
};
