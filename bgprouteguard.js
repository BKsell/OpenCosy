'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bgproute', prefix: 'BGPROUTE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBgprouteGuard: guard.evaluate,
  summarizeBgprouteGuard: guard.summarize,
  describeBgprouteGuard: guard.describe,
};
