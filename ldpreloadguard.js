'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ldpreload', prefix: 'LDPRELOAD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLdpreloadGuard: guard.evaluate,
  summarizeLdpreloadGuard: guard.summarize,
  describeLdpreloadGuard: guard.describe,
};
