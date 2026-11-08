'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jmxremote', prefix: 'JMXREMOTE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJmxremoteGuard: guard.evaluate,
  summarizeJmxremoteGuard: guard.summarize,
  describeJmxremoteGuard: guard.describe,
};
