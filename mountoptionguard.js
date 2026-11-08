'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mountoption', prefix: 'MOUNTOPTI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMountoptionGuard: guard.evaluate,
  summarizeMountoptionGuard: guard.summarize,
  describeMountoptionGuard: guard.describe,
};
