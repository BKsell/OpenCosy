'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rpathrunpath', prefix: 'RPATHRUNP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRpathrunpathGuard: guard.evaluate,
  summarizeRpathrunpathGuard: guard.summarize,
  describeRpathrunpathGuard: guard.describe,
};
