'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'uuid', prefix: 'UUID' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUuidGuard: guard.evaluate,
  summarizeUuidGuard: guard.summarize,
  describeUuidGuard: guard.describe,
};
