'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'enclave', prefix: 'ENCLAVE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEnclaveGuard: guard.evaluate,
  summarizeEnclaveGuard: guard.summarize,
  describeEnclaveGuard: guard.describe,
};
