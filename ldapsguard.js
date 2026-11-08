'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ldaps', prefix: 'LDAPS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLdapsGuard: guard.evaluate,
  summarizeLdapsGuard: guard.summarize,
  describeLdapsGuard: guard.describe,
};
