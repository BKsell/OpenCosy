'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'seccompfilter', prefix: 'SECCOMPFI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSeccompfilterGuard: guard.evaluate,
  summarizeSeccompfilterGuard: guard.summarize,
  describeSeccompfilterGuard: guard.describe,
};
