'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gyroscope', prefix: 'GYROSCOPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGyroscopeGuard: guard.evaluate,
  summarizeGyroscopeGuard: guard.summarize,
  describeGyroscopeGuard: guard.describe,
};
