'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'eaptls', prefix: 'EAPTLS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEaptlsGuard: guard.evaluate,
  summarizeEaptlsGuard: guard.summarize,
  describeEaptlsGuard: guard.describe,
};
