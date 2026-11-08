'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'magnetometer', prefix: 'MAGNETOME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMagnetometerGuard: guard.evaluate,
  summarizeMagnetometerGuard: guard.summarize,
  describeMagnetometerGuard: guard.describe,
};
