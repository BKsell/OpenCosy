'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'kioskmode', prefix: 'KIOSKMODE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKioskmodeGuard: guard.evaluate,
  summarizeKioskmodeGuard: guard.summarize,
  describeKioskmodeGuard: guard.describe,
};
