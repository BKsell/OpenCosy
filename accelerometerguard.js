'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'accelerometer', prefix: 'ACCELEROM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAccelerometerGuard: guard.evaluate,
  summarizeAccelerometerGuard: guard.summarize,
  describeAccelerometerGuard: guard.describe,
};
