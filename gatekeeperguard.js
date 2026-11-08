'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gatekeeper', prefix: 'GATEKEEPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGatekeeperGuard: guard.evaluate,
  summarizeGatekeeperGuard: guard.summarize,
  describeGatekeeperGuard: guard.describe,
};
