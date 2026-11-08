'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hkdf', prefix: 'HKDF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHkdfGuard: guard.evaluate,
  summarizeHkdfGuard: guard.summarize,
  describeHkdfGuard: guard.describe,
};
