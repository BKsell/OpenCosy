'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nativemenu', prefix: 'NATIVEMEN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNativemenuGuard: guard.evaluate,
  summarizeNativemenuGuard: guard.summarize,
  describeNativemenuGuard: guard.describe,
};
