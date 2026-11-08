'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'headerorder', prefix: 'HEADERORD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHeaderorderGuard: guard.evaluate,
  summarizeHeaderorderGuard: guard.summarize,
  describeHeaderorderGuard: guard.describe,
};
