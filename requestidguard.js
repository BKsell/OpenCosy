'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'requestid', prefix: 'REQUESTID' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRequestidGuard: guard.evaluate,
  summarizeRequestidGuard: guard.summarize,
  describeRequestidGuard: guard.describe,
};
