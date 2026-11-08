'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'customprotocol', prefix: 'CUSTOMPRO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCustomprotocolGuard: guard.evaluate,
  summarizeCustomprotocolGuard: guard.summarize,
  describeCustomprotocolGuard: guard.describe,
};
