'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dragdrop', prefix: 'DRAGDROP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDragdropGuard: guard.evaluate,
  summarizeDragdropGuard: guard.summarize,
  describeDragdropGuard: guard.describe,
};
