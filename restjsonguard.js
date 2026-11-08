'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'restjson', prefix: 'RESTJSON' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRestjsonGuard: guard.evaluate,
  summarizeRestjsonGuard: guard.summarize,
  describeRestjsonGuard: guard.describe,
};
