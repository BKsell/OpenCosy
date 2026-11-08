'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'etagweak', prefix: 'ETAGWEAK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEtagweakGuard: guard.evaluate,
  summarizeEtagweakGuard: guard.summarize,
  describeEtagweakGuard: guard.describe,
};
