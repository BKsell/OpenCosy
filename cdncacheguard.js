'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cdncache', prefix: 'CDNCACHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCdncacheGuard: guard.evaluate,
  summarizeCdncacheGuard: guard.summarize,
  describeCdncacheGuard: guard.describe,
};
