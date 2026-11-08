'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'chroot', prefix: 'CHROOT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChrootGuard: guard.evaluate,
  summarizeChrootGuard: guard.summarize,
  describeChrootGuard: guard.describe,
};
