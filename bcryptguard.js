'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bcrypt', prefix: 'BCRYPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBcryptGuard: guard.evaluate,
  summarizeBcryptGuard: guard.summarize,
  describeBcryptGuard: guard.describe,
};
