'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'salt', prefix: 'SALT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSaltGuard: guard.evaluate,
  summarizeSaltGuard: guard.summarize,
  describeSaltGuard: guard.describe,
};
