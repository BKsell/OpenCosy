'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'truststore', prefix: 'TRUSTSTOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTruststoreGuard: guard.evaluate,
  summarizeTruststoreGuard: guard.summarize,
  describeTruststoreGuard: guard.describe,
};
