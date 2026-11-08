'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'clientcert', prefix: 'CLIENTCER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateClientcertGuard: guard.evaluate,
  summarizeClientcertGuard: guard.summarize,
  describeClientcertGuard: guard.describe,
};
