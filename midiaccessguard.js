'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'midiaccess', prefix: 'MIDIACCES' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMidiaccessGuard: guard.evaluate,
  summarizeMidiaccessGuard: guard.summarize,
  describeMidiaccessGuard: guard.describe,
};
