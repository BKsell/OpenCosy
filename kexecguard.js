'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'kexec', prefix: 'KEXEC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKexecGuard: guard.evaluate,
  summarizeKexecGuard: guard.summarize,
  describeKexecGuard: guard.describe,
};
