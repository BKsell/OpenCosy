'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'powersave', prefix: 'POWERSAVE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePowersaveGuard: guard.evaluate,
  summarizePowersaveGuard: guard.summarize,
  describePowersaveGuard: guard.describe,
};
