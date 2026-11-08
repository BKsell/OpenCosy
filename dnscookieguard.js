'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dnscookie', prefix: 'DNSCOOKIE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDnscookieGuard: guard.evaluate,
  summarizeDnscookieGuard: guard.summarize,
  describeDnscookieGuard: guard.describe,
};
