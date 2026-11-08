'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sseref', prefix: 'SSEREF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSserefGuard: guard.evaluate,
  summarizeSserefGuard: guard.summarize,
  describeSserefGuard: guard.describe,
};
