'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mdsattack', prefix: 'MDSATTACK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMdsattackGuard: guard.evaluate,
  summarizeMdsattackGuard: guard.summarize,
  describeMdsattackGuard: guard.describe,
};
