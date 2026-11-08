'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'capnp', prefix: 'CAPNP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCapnpGuard: guard.evaluate,
  summarizeCapnpGuard: guard.summarize,
  describeCapnpGuard: guard.describe,
};
