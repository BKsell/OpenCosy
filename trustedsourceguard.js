'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'trustedsource', prefix: 'TRUSTEDSO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTrustedsourceGuard: guard.evaluate,
  summarizeTrustedsourceGuard: guard.summarize,
  describeTrustedsourceGuard: guard.describe,
};
