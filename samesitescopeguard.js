'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'samesitescope', prefix: 'SAMESITES' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSamesitescopeGuard: guard.evaluate,
  summarizeSamesitescopeGuard: guard.summarize,
  describeSamesitescopeGuard: guard.describe,
};
