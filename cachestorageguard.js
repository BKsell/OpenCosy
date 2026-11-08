'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cachestorage', prefix: 'CACHESTOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCachestorageGuard: guard.evaluate,
  summarizeCachestorageGuard: guard.summarize,
  describeCachestorageGuard: guard.describe,
};
