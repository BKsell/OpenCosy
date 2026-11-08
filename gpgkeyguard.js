'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gpgkey', prefix: 'GPGKEY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGpgkeyGuard: guard.evaluate,
  summarizeGpgkeyGuard: guard.summarize,
  describeGpgkeyGuard: guard.describe,
};
