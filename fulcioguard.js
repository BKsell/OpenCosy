'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fulcio', prefix: 'FULCIO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFulcioGuard: guard.evaluate,
  summarizeFulcioGuard: guard.summarize,
  describeFulcioGuard: guard.describe,
};
