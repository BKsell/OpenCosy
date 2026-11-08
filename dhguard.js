'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dh', prefix: 'DH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDhGuard: guard.evaluate,
  summarizeDhGuard: guard.summarize,
  describeDhGuard: guard.describe,
};
